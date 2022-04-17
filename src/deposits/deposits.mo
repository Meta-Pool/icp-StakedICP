import Array "mo:base/Array";
import AssocList "mo:base/AssocList";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Debug "mo:base/Debug";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Hash "mo:base/Hash";
import Int "mo:base/Int";
import Iter "mo:base/Iter";
import List "mo:base/List";
import Nat64 "mo:base/Nat64";
import Nat "mo:base/Nat";
import Option "mo:base/Option";
import Order "mo:base/Order";
import P "mo:base/Prelude";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Trie "mo:base/Trie";

import Account      "./Account";
import Hex          "./Hex";
import Owners       "./Owners";
import Referrals    "./Referrals";
import Governance "Governance";
import Ledger "Ledger";
import Token "../DIP20/motoko/src/token";

shared(init_msg) actor class Deposits(args: {
    governance: Principal;
    ledger: Principal;
    ledgerCandid: Principal;
    token: Principal;
    owners: [Principal];
    stakingNeuron: ?{ id : { id : Nat64 }; accountId : Text };
}) = this {
    private let referralTracker = Referrals.Tracker();
    private stable var stableReferralData : ?Referrals.UpgradeData = null;

    // Cost to transfer ICP on the ledger
    let icpFee: Nat = 10_000;
    let minimumDeposit: Nat = icpFee*10;

    // Makes date math simpler
    let second : Int = 1_000_000_000;
    let minute : Int = 60 * second;
    let hour : Int = 60 * minute;
    let day : Int = 24 * hour;

    // For apr calcs
    let microbips : Nat64 = 100_000_000;


    type NeuronId = { id : Nat64; };

    // Copied from Token due to compiler weirdness
    type TxReceipt = {
        #Ok: Nat;
        #Err: {
            #InsufficientAllowance;
            #InsufficientBalance;
            #ErrorOperationStyle;
            #Unauthorized;
            #LedgerTrap;
            #ErrorTo;
            #Other: Text;
            #BlockUsed;
            #AmountTooSmall;
        };
    };

    type ApplyInterestResult = {
        timestamp : Time.Time;
        supply : {
            before : Ledger.Tokens;
            after : Ledger.Tokens;
        };
        applied : Ledger.Tokens;
        remainder : Ledger.Tokens;
        totalHolders: Nat;
        flush : ?TxReceipt;
        affiliatePayouts: Nat;
    };

    type WithdrawPendingDepositsResult = {
      args : Ledger.TransferArgs;
      result : Ledger.TransferResult;
    };

    public type StakingNeuron = {
        id : NeuronId;
        accountId : Account.AccountIdentifier;
    };

    private stable var governance : Governance.Interface = actor(Principal.toText(args.governance));
    private stable var ledger : Ledger.Self = actor(Principal.toText(args.ledger));

    private stable var token : Token.Token = actor(Principal.toText(args.token));
    private stable var stakingNeuron_ : ?StakingNeuron = switch (args.stakingNeuron) {
        case (null) { null };
        case (?n) {
            ?{
                id = n.id;
                accountId = switch (Account.fromText(n.accountId)) {
                    case (#err(_)) { P.unreachable() };
                    case (#ok(x)) { x };
                };
            };
        };
    };

    private stable var balances : Trie.Trie<Principal, Nat64> = Trie.empty();
    private stable var pendingMints : Trie.Trie<Principal, Nat64> = Trie.empty();
    private stable var snapshot : ?[(Principal, Nat)] = null;

    private stable var appliedInterestEntries : [ApplyInterestResult] = [];
    private var appliedInterest : Buffer.Buffer<ApplyInterestResult> = Buffer.Buffer(0);
    private stable var meanAprMicrobips : Nat64 = 0;

    // ===== OWNER FUNCTIONS =====

    private let owners = Owners.Owners(args.owners);
    private stable var stableOwners : ?Owners.UpgradeData = null;

    public shared(msg) func addOwner(candidate: Principal) {
        owners.add(msg.caller, candidate);
    };

    public shared(msg) func removeOwner(candidate: Principal) {
        owners.remove(msg.caller, candidate);
    };

    // ===== GETTER/SETTER FUNCTIONS =====

    public shared(msg) func setToken(_token: Principal) {
        owners.require(msg.caller);
        token := actor(Principal.toText(_token));
    };

    public shared(msg) func stakingNeuron(): async ?{ id : NeuronId ; accountId : Text } {
        return switch (stakingNeuron_) {
            case (null) { null };
            case (?n) {
                ?{
                    id = n.id;
                    accountId = Account.toText(n.accountId);
                }
            };
        };
    };

    private func stakingNeuronBalance(): async ?Nat64 {
        return switch (stakingNeuron_) {
            case (null) { null };
            case (?n) {
                ?(await ledger.account_balance({
                    account = Blob.toArray(n.accountId);
                })).e8s;
            };
        };
    };

    public shared(msg) func setStakingNeuron(n: { id : NeuronId ; accountId : Text }) {
        owners.require(msg.caller);
        stakingNeuron_ := ?{
            id = n.id;
            accountId = switch (Account.fromText(n.accountId)) {
                case (#err(_)) {
                    assert(false);
                    loop {};
                };
                case (#ok(x)) { x };
            };
        };
    };

    public shared(msg) func accountId() : async Text {
        return Account.toText(accountIdBlob());
    };

    private func accountIdBlob() : Account.AccountIdentifier {
        return Account.fromPrincipal(Principal.fromActor(this), Account.defaultSubaccount());
    };

    // ===== METRICS FUNCTIONS =====

    private stable var metricsCanister : ?Principal = null;
    public shared(msg) func setMetrics(m: ?Principal) {
        owners.require(msg.caller);
        metricsCanister := m;
    };

    public type Metrics = {
        aprMicrobips: Nat64;
        balances: [(Text, Nat64)];
        stakingNeuronBalance: ?Nat64;
        referralAffiliatesCount: Nat;
        referralLeads: [Referrals.LeadMetrics];
        referralPayoutsSum: Nat;
    };

    public shared(msg) func metrics() : async Metrics {
        if (not owners.is(msg.caller)) {
            switch (metricsCanister) {
                case (null) {
                    assert(false);
                    loop {};
                };
                case (?expected) {
                    assert(msg.caller == expected);
                };
            };
        };

        var balance = (await ledger.account_balance({
            account = Blob.toArray(accountIdBlob());
        })).e8s;
        for ((_, amount) in Trie.iter(balances)) {
            balance := balance + amount;
        };
        return {
            aprMicrobips = await aprMicrobips();
            balances = [
                ("ICP", balance),
                ("cycles", Nat64.fromNat(ExperimentalCycles.balance()))
            ];
            stakingNeuronBalance = await stakingNeuronBalance();
            referralAffiliatesCount = referralTracker.affiliatesCount();
            referralLeads = referralTracker.leadMetrics();
            referralPayoutsSum = referralTracker.payoutsSum();
        };
    };

    // ===== INTEREST FUNCTIONS =====

    private func sortInterestByTime(a: ApplyInterestResult, b: ApplyInterestResult): Order.Order {
      Int.compare(a.timestamp, b.timestamp)
    };

    // Buffers have not sort, implement it ourselves.
    private func sortBuffer<A>(buf: Buffer.Buffer<A>, cmp: (A, A) -> Order.Order): Buffer.Buffer<A> {
        let result = Buffer.Buffer<A>(buf.size());
        for (x in Array.sort(buf.toArray(), cmp).vals()) {
            result.add(x);
        };
        result
    };

    public shared(msg) func applyInterest(interest: Nat64, when: ?Time.Time) : async ApplyInterestResult {
        owners.require(msg.caller);

        let now = Option.get(when, Time.now());

        let result = await applyInterestToToken(now, Nat64.toNat(interest));

        appliedInterest.add(result);
        appliedInterest := sortBuffer(appliedInterest, sortInterestByTime);

        updateMeanAprMicrobips();

        return result;
    };

    private func getAllHolders(): async [(Principal, Nat)] {
        let info = await token.getTokenInfo();
        // *2 here is because this is not atomic, so if anyone joins in the
        // meantime.
        return await token.getHolders(0, info.holderNumber*2);
    };

    private func applyInterestToToken(now: Time.Time, interest: Nat): async ApplyInterestResult {
        let nextHolders = await getAllHolders();
        let holders = Option.get(snapshot, nextHolders);

        // Calculate everything
        var beforeSupply : Nat = 0;
        for (i in Iter.range(0, holders.size() - 1)) {
            let (_, balance) = holders[i];
            beforeSupply += balance;
        };

        if (interest == 0) {
            return {
                timestamp = now;
                supply = {
                    before = { e8s = Nat64.fromNat(beforeSupply) };
                    after = { e8s = Nat64.fromNat(beforeSupply) };
                };
                applied = { e8s = 0 : Nat64 };
                remainder = { e8s = 0 : Nat64 };
                totalHolders = holders.size();
                flush = null;
                affiliatePayouts = 0;
            };
        };
        assert(interest > 0);

        var remainder = interest;

        var mints = Buffer.Buffer<(Principal, Nat)>(holders.size());
        var afterSupply : Nat = 0;
        for (i in Iter.range(0, holders.size() - 1)) {
            let (to, balance) = holders[i];
            let share = (interest * balance) / beforeSupply;
            if (share > 0) {
                mints.add((to, share));
            };
            assert(share <= remainder);
            remainder -= share;
            afterSupply += balance + share;
        };
        assert(afterSupply >= beforeSupply);
        assert(interest >= remainder);
        assert(afterSupply == beforeSupply + interest - remainder);

        // Queue the mints
        var affiliatePayouts : Nat = 0;
        for ((to, share) in mints.vals()) {
            Debug.print("interest: " # debug_show(share) # " to " # debug_show(to));
            ignore queueMint(to, Nat64.fromNat(share));
            switch (referralTracker.payout(to, share)) {
                case (null) {};
                case (?(affiliate, payout)) {
                    Debug.print("affiliate: " # debug_show(payout) # " to " # debug_show(affiliate));
                    ignore queueMint(affiliate, Nat64.fromNat(payout));
                    affiliatePayouts := affiliatePayouts + payout;
                };
            }
        };

        // If there is one e8s left, we'll take it, to make sure the accounts
        // match up.
        if (remainder > 0) {
            let root = Principal.fromActor(this);
            Debug.print("remainder: " # debug_show(remainder) # " to " # debug_show(root));
            ignore queueMint(root, Nat64.fromNat(remainder));
            afterSupply += remainder;
            remainder := 0;
        };

        // Do the mints.
        let flush = await flushAllMints();

        // Update the snapshot for next time.
        snapshot := ?nextHolders;

        return {
            timestamp = now;
            supply = {
                before = { e8s = Nat64.fromNat(beforeSupply) };
                after = { e8s = Nat64.fromNat(afterSupply) };
            };
            applied = { e8s = Nat64.fromNat(afterSupply - beforeSupply) };
            remainder = { e8s = Nat64.fromNat(remainder) };
            totalHolders = holders.size();
            flush = ?flush;
            affiliatePayouts = affiliatePayouts;
        };
    };

    // 1 microbip is 0.000000001%
    // convert the result to apy % with:
    // (((1+(aprMicrobips / 100_000_000))^365.25) - 1)*100
    // e.g. 53900 microbips = 21.75% APY
    private func updateMeanAprMicrobips() {
        meanAprMicrobips := 0;

        if (appliedInterest.size() == 0) {
            return;
        };

        let last = appliedInterest.get(appliedInterest.size() - 1);

        // supply.before should always be > 0, because initial supply is 1, but...
        assert(last.supply.before.e8s > 0);

        // 7 days from the last time we applied interest, truncated to the utc day start.
        let start = ((last.timestamp - (day * 6)) / day) * day;

        // sum all interest applications that are in that period.
        var i : Nat = appliedInterest.size();
        var sum : Nat64 = 0;
        var earliest : Time.Time  = last.timestamp;
        label range while (i > 0) {
            i := i - 1;
            let interest = appliedInterest.get(i);
            if (interest.timestamp < start) {
                break range;
            };
            sum := sum + ((microbips * interest.supply.after.e8s) / interest.supply.before.e8s) - microbips;
            earliest := interest.timestamp;
        };
        // truncate to start of first day where we found an application.
        // (in case we didn't have 7 days of applications)
        earliest := (earliest / day) * day;
        // end of last day
        let latest = ((last.timestamp / day) * day) + day;
        // Find the number of days we've spanned
        let span = Nat64.fromNat(Int.abs((latest - earliest) / day));

        // Find the mean
        meanAprMicrobips := sum / span;

        Debug.print("meanAprMicrobips: " # debug_show(meanAprMicrobips));
    };

    public query func aprMicrobips() : async Nat64 {
        return meanAprMicrobips;
    };

    // ===== REFERRAL FUNCTIONS =====

    public type ReferralStats = {
        code: Text;
        count: Nat;
        earned: Nat;
    };

    public shared(msg) func getReferralStats(): async ReferralStats {
        let stats = referralTracker.getStats(msg.caller);
        return {
            code = await referralTracker.getCode(msg.caller);
            count = stats.count;
            earned = stats.earned;
        };
    };

    // ===== DEPOSIT FUNCTIONS =====

    // Return the account ID specific to this user's subaccount
    public shared(msg) func getDepositAddress(code: ?Text): async Text {
        Debug.print("[Referrals.touch] user: " # debug_show(msg.caller) # ", code: " # debug_show(code));
        referralTracker.touch(msg.caller, code);
        Account.toText(Account.fromPrincipal(Principal.fromActor(this), Account.principalToSubaccount(msg.caller)));
    };

    public type DepositErr = {
        #BalanceLow;
        #TransferFailure;
    };

    public type DepositReceipt = {
        #Ok: Nat;
        #Err: DepositErr;
    };

    private func principalKey(p: Principal) : Trie.Key<Principal> {
        return {
            key = p;
            hash = Principal.hash(p);
        };
    };

    // After user transfers ICP to the target subaccount
    public shared(msg) func depositIcp(): async DepositReceipt {
        let neuron = stakingNeuron_;
        let to = switch (neuron) {
            case (null) {
                // contract not configured.
                assert(false);
                loop {};
            };
            case (?neuron) {
                Blob.toArray(neuron.accountId)
            };
        };

        // Calculate target subaccount
        let subaccount = Account.principalToSubaccount(msg.caller);
        let source_account = Account.fromPrincipal(Principal.fromActor(this), subaccount);

        // Check ledger for value
        let balance = await ledger.account_balance({ account = Blob.toArray(source_account) });

        // TODO: Refactor this to a Triemap
        let key = principalKey(msg.caller);
        balances := Trie.put(balances, key, Principal.equal, balance.e8s).0;

        // Transfer to staking neuron
        if (Nat64.toNat(balance.e8s) <= minimumDeposit) {
            return #Err(#BalanceLow);
        };
        let fee = { e8s = Nat64.fromNat(icpFee) };
        let amount = { e8s = balance.e8s - fee.e8s };
        let icp_receipt = await ledger.transfer({
            memo : Nat64    = 0;
            from_subaccount = ?Blob.toArray(subaccount);
            to              = to;
            amount          = amount;
            fee             = fee;
            created_at_time = ?{ timestamp_nanos = Nat64.fromNat(Int.abs(Time.now())) };
        });

        switch icp_receipt {
            case ( #Err _) {
                return #Err(#TransferFailure);
            };
            case _ {};
        };

        balances := Trie.put(balances, key, Principal.equal, 0 : Nat64).0;

        // Mint the new tokens
        Debug.print("[Referrals.convert] user: " # debug_show(msg.caller));
        referralTracker.convert(msg.caller);
        ignore queueMint(msg.caller, amount.e8s);
        ignore await flushMint(msg.caller);

        // Refresh the neuron balance, if we deposited directly
        switch (neuron) {
            case (null) {
                Debug.print("Staking neuron not configured for deposit");
            };
            case (?neuron) {
                Debug.print("Staking neuron refreshing: " # debug_show(neuron.id));
                let refresh = await governance.manage_neuron({
                    id = null;
                    command = ?#ClaimOrRefresh({ by = ?#NeuronIdOrSubaccount({}) });
                    neuron_id_or_subaccount = ?#NeuronId(neuron.id);
                });
            };
        };

        return #Ok(Nat64.toNat(amount.e8s));
    };

    // First we queue them locally, in case the async mint call fails.
    private func queueMint(to : Principal, amount : Nat64) : Nat64 {
        let key = principalKey(to);
        let existing = Option.get(Trie.find(pendingMints, key, Principal.equal), 0 : Nat64);
        let total = existing + amount;
        pendingMints := Trie.replace(pendingMints, key, Principal.equal, ?total).0;
        return total;
    };

    private func flushMint(to : Principal) : async TxReceipt {
        let key = principalKey(to);
        let total = Option.get(Trie.find(pendingMints, key, Principal.equal), 0 : Nat64);
        if (total == 0) {
            return #Err(#AmountTooSmall);
        };
        Debug.print("minting: " # debug_show(total) # " to " # debug_show(to));
        let result = await token.mint(to, Nat64.toNat(total));
        pendingMints := Trie.remove(pendingMints, key, Principal.equal).0;
        return result;
    };

    private func flushAllMints() : async TxReceipt {
        let size = Trie.size(pendingMints);
        for ((to, _) in Trie.iter(pendingMints)) {
            switch (await flushMint(to)) {
                case (#Ok(_)) { };
                case (err) { return err };
            };
        };
        return #Ok(size);
    };

    // ===== UPGRADE FUNCTIONS =====

    system func preupgrade() {
        // convert the buffer to a stable array
        appliedInterestEntries := appliedInterest.toArray();

        stableReferralData := referralTracker.preupgrade();

        stableOwners := owners.preupgrade();
    };

    system func postupgrade() {
        // convert the stable array back to a buffer.
        appliedInterest := Buffer.Buffer(appliedInterestEntries.size());
        for (x in appliedInterestEntries.vals()) {
            appliedInterest.add(x);
        };

        referralTracker.postupgrade(stableReferralData);
        stableReferralData := null;

        owners.postupgrade(stableOwners);
        stableOwners := null;
    };

    public shared(msg) func setInitialSnapshot(): async (Text, [(Principal, Nat)]) {
        owners.require(msg.caller);
        switch (snapshot) {
            case (null) {
                let holders = await getAllHolders();
                snapshot := ?holders;
                return ("new", holders);
            };
            case (?holders) {
                return ("existing", holders);
            };
        };
    };
};
