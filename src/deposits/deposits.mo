import Array "mo:base/Array";
import AssocList "mo:base/AssocList";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Debug "mo:base/Debug";
import Error "mo:base/Error";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Hash "mo:base/Hash";
import Int "mo:base/Int";
import Iter "mo:base/Iter";
import List "mo:base/List";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Nat "mo:base/Nat";
import Option "mo:base/Option";
import Order "mo:base/Order";
import P "mo:base/Prelude";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import TrieMap "mo:base/TrieMap";

import Account      "./Account";
import Hex          "./Hex";
import Neurons      "./Neurons";
import Owners       "./Owners";
import Referrals    "./Referrals";
import Staking      "./Staking";
import Util         "./Util";
import Withdrawals  "./Withdrawals";
import Governance "../governance/Governance";
import Ledger "../ledger/Ledger";
import Token "../DIP20/motoko/src/token";

// The deposits canister is the main backend canister for StakedICP. It
// forwards calls to several submodules, and manages daily recurring jobs via
// heartbeats.
shared(init_msg) actor class Deposits(args: {
    governance: Principal;
    ledger: Principal;
    ledgerCandid: Principal;
    token: Principal;
    owners: [Principal];
    stakingNeuron: ?{ id : { id : Nat64 }; accountId : Text };
}) = this {
    // Referrals subsystem
    private let referralTracker = Referrals.Tracker();
    private stable var stableReferralData : ?Referrals.UpgradeData = null;

    // Proposal-based neuron management subsystem
    private let neurons = Neurons.Manager({ governance = args.governance });
    private stable var stableNeuronsData : ?Neurons.UpgradeData = null;

    // Staking management subsystem
    private let staking = Staking.Manager({
        governance = args.governance;
        neurons = neurons;
    });
    private stable var stableStakingData : ?Staking.UpgradeData = null;

    // Withdrawals management subsystem
    private let withdrawals = Withdrawals.Manager({
        token = args.token;
        ledger = args.ledger;
        neurons = neurons;
    });
    private stable var stableWithdrawalsData : ?Withdrawals.UpgradeData = null;


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
        affiliatePayouts: Nat;
    };

    type WithdrawPendingDepositsResult = {
      args : Ledger.TransferArgs;
      result : Ledger.TransferResult;
    };

    public type Neuron = {
        id : NeuronId;
        accountId : Account.AccountIdentifier;
    };

    private stable var governance : Governance.Interface = actor(Principal.toText(args.governance));
    private stable var ledger : Ledger.Self = actor(Principal.toText(args.ledger));

    private stable var token : Token.Token = actor(Principal.toText(args.token));

    private var pendingMints = TrieMap.TrieMap<Principal, Nat64>(Principal.equal, Principal.hash);
    private stable var stablePendingMints : ?[(Principal, Nat64)] = null;

    private stable var snapshot : ?[(Principal, Nat)] = null;

    private stable var appliedInterestEntries : [ApplyInterestResult] = [];
    private var appliedInterest : Buffer.Buffer<ApplyInterestResult> = Buffer.Buffer(0);
    private stable var meanAprMicrobips : Nat64 = 0;

    private stable var cachedLedgerBalanceE8s : Nat64 = 0;

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

    public shared(msg) func stakingNeurons(): async [{ id : NeuronId ; accountId : Text }] {
        staking.list()
    };

    public shared(msg) func stakingNeuronBalances(): async [(Nat64, Nat64)] {
        staking.balances()
    };

    private func stakingNeuronBalance(): Nat64 {
        var sum : Nat64 = 0;
        for ((id, balance) in staking.balances().vals()) {
            sum += balance;
        };
        sum
    };

    private func stakingNeuronMaturityE8s() : async Nat64 {
        let maturities = await neurons.maturities(staking.ids());
        var sum : Nat64 = 0;
        for ((id, maturities) in maturities.vals()) {
            sum += maturities;
        };
        sum
    };

    // Idempotently add a neuron to the tracked staking neurons. The neurons
    // added here must be manageable by the proposal neuron. The starting
    // balance will be minted as stICP to the canister's token account.
    public shared(msg) func addStakingNeuron(id: Nat64): async Neurons.NeuronResult {
        owners.require(msg.caller);
        switch (await neurons.refresh(id)) {
            case (#err(err)) { #err(err) };
            case (#ok(neuron)) {
                let isNew = staking.addOrRefresh(neuron);
                if isNew {
                    let canister = Principal.fromActor(this);
                    ignore queueMint(canister, neuron.cachedNeuronStakeE8s);
                    ignore flushMint(canister);
                };
                #ok(neuron)
            };
        }
    };

    public shared(msg) func proposalNeuron(): async ?Neurons.Neuron {
        neurons.getProposalNeuron()
    };

    public shared(msg) func setProposalNeuron(id: Nat64): async Neurons.NeuronResult {
        owners.require(msg.caller);
        let neuron = await neurons.refresh(id);
        Result.iterate(neuron, neurons.setProposalNeuron);
        neuron
    };

    public shared(msg) func accountId() : async Text {
        return Account.toText(accountIdBlob());
    };

    private func accountIdBlob() : Account.AccountIdentifier {
        return Account.fromPrincipal(Principal.fromActor(this), Account.defaultSubaccount());
    };

    // Getter for the current APR in microbips
    public query func aprMicrobips() : async Nat64 {
        return meanAprMicrobips;
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
        lastHeartbeatAt: Time.Time;
        lastHeartbeatOk: Bool;
        lastHeartbeatInterestApplied: Nat64;
        pendingMints: Nat64;
        // TODO: Add neurons metrics
    };

    // Expose metrics to track canister performance, and behaviour. These are
    // ingested and served by the "metrics" canister.
    public shared(msg) func metrics() : async Metrics {
        if (not owners.is(msg.caller)) {
            switch (metricsCanister) {
                case (null) {
                    throw Error.reject("metrics canister missing");
                };
                case (?expected) {
                    assert(msg.caller == expected);
                };
            };
        };

        var balance = (await ledger.account_balance({
            account = Blob.toArray(accountIdBlob());
        })).e8s;
        var pendingMintAmount : Nat64 = 0;
        for (amount in pendingMints.vals()) {
            pendingMintAmount += amount;
        };
        return {
            aprMicrobips = meanAprMicrobips;
            balances = [
                ("ICP", balance),
                ("cycles", Nat64.fromNat(ExperimentalCycles.balance()))
            ];
            stakingNeuronBalance = ?stakingNeuronBalance();
            referralAffiliatesCount = referralTracker.affiliatesCount();
            referralLeads = referralTracker.leadMetrics();
            referralPayoutsSum = referralTracker.payoutsSum();
            lastHeartbeatAt = lastHeartbeatAt;
            lastHeartbeatOk = lastHeartbeatError == null;
            lastHeartbeatInterestApplied = switch (lastHeartbeatApply) {
                case (?#ok({applied; remainder; affiliatePayouts})) {
                    applied.e8s + remainder.e8s + Nat64.fromNat(affiliatePayouts)
                };
                case (_) { 0 };
            };
            pendingMints = pendingMintAmount;
        };
    };

    // ===== INTEREST FUNCTIONS =====

    // helper to short ApplyInterestResults
    private func sortInterestByTime(a: ApplyInterestResult, b: ApplyInterestResult): Order.Order {
      Int.compare(a.timestamp, b.timestamp)
    };

    // Buffers don't have sort, implement it ourselves.
    private func sortBuffer<A>(buf: Buffer.Buffer<A>, cmp: (A, A) -> Order.Order): Buffer.Buffer<A> {
        let result = Buffer.Buffer<A>(buf.size());
        for (x in Array.sort(buf.toArray(), cmp).vals()) {
            result.add(x);
        };
        result
    };

    // List all neurons ready for disbursal. We will disburse them into the
    // deposit canister's default account, like it is a new deposit.
    // flushPendingDeposits will then route it to the right place.
    public shared(msg) func listNeuronsToDisburse(): async [Neurons.Neuron] {
        owners.require(msg.caller);
        withdrawals.listNeuronsToDisburse()
    };

    // Once we've disbursed them, remove them from the withdrawals neuron tracking
    public shared(msg) func removeDisbursedNeurons(ids: [Nat64]): async [Neurons.Neuron] {
        owners.require(msg.caller);
        withdrawals.removeDisbursedNeurons(ids)
    };

    // In case there was an issue with the automatic daily heartbeat, the
    // canister owner can call it manually. Repeated calling should be
    // effectively idempotent.
    public shared(msg) func manualHeartbeat(when: ?Time.Time): async () {
        owners.require(msg.caller);
        await dailyHeartbeat(when);
    };

    // called every day by the heartbeat function.
    private func dailyHeartbeat(when: ?Time.Time) : async () {
        // Reset all the daily heartbeat state where we record the results
        lastHeartbeatError := null;
        lastHeartbeatApply := null;
        lastHeartbeatMergeDissolving := null;
        lastHeartbeatFlush := null;
        lastHeartbeatRefresh := null;
        lastHeartbeatSplit := null;

        // Merge the interest
        await applyInterest(when);

        // Flush pending deposits
        await flushPendingDeposits();

        // merge the maturity for our dissolving withdrawal neurons
        await mergeWithdrawalMaturity();

        // Split off as many staking neurons as we need to ensure withdrawals
        // will be satisfied.
        //
        // Note: This needs to happen *after* everything above, hence the awaits.
        ignore splitNewWithdrawalNeurons();
    };

    private func mergeMaturities(ids: [Nat64], percentage: Nat32): async [Neurons.Neuron] {
        Array.mapFilter<Result.Result<Neurons.Neuron, Neurons.NeuronsError>, Neurons.Neuron>(
            await neurons.mergeMaturities(withdrawals.ids(), percentage),
            func(r) { Result.toOption(r) },
        )
    };

    // Distribute newly earned interest to token holders.
    private func applyInterest(when: ?Time.Time) : async () {
        let now = Option.get(when, Time.now());

        // take a snapshot of the holders for tomorrow's interest.
        let nextHolders = await getAllHolders();

        // See how much maturity we have pending
        let interest = await stakingNeuronMaturityE8s();
        if (interest <= 10_000) {
            return;
        };

        // Note: We might "leak" a tiny bit of interest here because maturity
        // could increase before we merge. It would be ideal if the NNS allowed
        // specify maturity to merge as an e8s, but alas.
        let merges = await mergeMaturities(staking.ids(), 100);
        for (n in merges.vals()) {
            ignore staking.addOrRefresh(n);
        };

        // Apply the interest to the holders
        let apply = applyInterestToToken(
            now,
            Nat64.toNat(interest),
            Option.get(snapshot, nextHolders)
        );

        // Update the snapshot for next time.
        snapshot := ?nextHolders;

        // Update the APY calculation
        appliedInterest.add(apply);
        appliedInterest := sortBuffer(appliedInterest, sortInterestByTime);
        updateMeanAprMicrobips();

        // Save the result in the daily heartbeat where this is called from.
        lastHeartbeatApply := ?#ok(apply);
    };

    // Use new incoming deposits to attempt to rebalance the buckets, where
    // "the buckets" are:
    // - pending withdrawals
    // - ICP in the canister
    // - staking neurons
    private func flushPendingDeposits(): async () {
        let tokenE8s = Nat64.fromNat((await token.getMetadata()).totalSupply);
        let totalBalance = _availableBalance();

        if (totalBalance == 0) {
            return;
        };

        let applied = withdrawals.applyIcp(totalBalance);
        let balance = totalBalance - Nat64.min(totalBalance, applied);
        if (balance == 0) {
            return;
        };

        let transfers = staking.depositIcp(tokenE8s, balance, null);
        for (transfer in transfers.vals()) {
            // Start the transfer. Best effort here. If the transfer fails,
            // it'll be retried next time. But not awaiting means this function
            // is atomic.
            ignore ledger.transfer(transfer);
        };
        if (transfers.size() > 0) {
            // If we did outbound transfers, refresh the ledger balance afterwards.
            ignore refreshAvailableBalance();
        };

        // Save the result in the daily heartbeat where this is called from.
        lastHeartbeatFlush := ?transfers;

        // Update the staked neuron balances after they've been topped up
        let refresh = await refreshAllStakingNeurons();
        lastHeartbeatRefresh := refresh;
    };

    private func getAllHolders(): async [(Principal, Nat)] {
        let info = await token.getTokenInfo();
        // *2 here is because this is not atomic, so if anyone joins in the
        // meantime.
        return await token.getHolders(0, info.holderNumber*2);
    };

    // Calculate shares owed and distribute interest to token holders.
    private func applyInterestToToken(now: Time.Time, interest: Nat, holders: [(Principal, Nat)]): ApplyInterestResult {
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
                affiliatePayouts = 0;
            };
        };

        var holdersPortion = (interest * 9) / 10;
        var remainder = interest;

        // Calculate the holders portions
        var mints = Buffer.Buffer<(Principal, Nat)>(holders.size());
        var applied : Nat = 0;
        for (i in Iter.range(0, holders.size() - 1)) {
            let (to, balance) = holders[i];
            let share = (holdersPortion * balance) / beforeSupply;
            if (share > 0) {
                mints.add((to, share));
            };
            assert(share <= remainder);
            remainder -= share;
            applied += share;
        };
        assert(applied + remainder == interest);
        assert(holdersPortion >= remainder);

        // Queue the mints & affiliate payouts
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
                    assert(payout <= remainder);
                    remainder -= payout;
                };
            }
        };

        // Deal with our share. For now, just mint it to this canister.
        if (remainder > 0) {
            let root = Principal.fromActor(this);
            Debug.print("remainder: " # debug_show(remainder) # " to " # debug_show(root));
            ignore queueMint(root, Nat64.fromNat(remainder));
            applied += remainder;
            remainder := 0;
        };

        // Check everything matches up
        assert(applied+affiliatePayouts+remainder == interest);

        return {
            timestamp = now;
            supply = {
                before = { e8s = Nat64.fromNat(beforeSupply) };
                after = { e8s = Nat64.fromNat(beforeSupply+applied+affiliatePayouts) };
            };
            applied = { e8s = Nat64.fromNat(applied) };
            remainder = { e8s = Nat64.fromNat(remainder) };
            totalHolders = holders.size();
            affiliatePayouts = affiliatePayouts;
        };
    };

    // Recalculate and update the cached mean interest for the last 7 days.
    //
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

        // 7 days from the last time we applied interest, truncated to the utc Day start.
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
            let after = interest.applied.e8s + Nat64.fromNat(interest.affiliatePayouts) + interest.remainder.e8s + interest.supply.before.e8s;
            sum := sum + ((microbips * after) / interest.supply.before.e8s) - microbips;
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

    // Refresh all neurons, fetching current data from the NNS. This is
    // needed e.g. if we have transferred more ICP into a staking neuron,
    // to update the cached balances.
    private func refreshAllStakingNeurons(): async ?Neurons.NeuronsError {
        for (id in staking.ids().vals()) {
            switch (await neurons.refresh(id)) {
                case (#err(err)) { return ?err };
                case (#ok(neuron)) {
                    ignore staking.addOrRefresh(neuron);
                };
            };
        };
        return null;
    };

    private func mergeWithdrawalMaturity() : async () {
        // Merge maturity on dissolving neurons. Merged maturity here will be
        // disbursed when the neuron is dissolved, and will be a "bonus" put
        // towards filling pending withdrawals early.
        let merge = await mergeMaturities(withdrawals.ids(), 100);
        ignore withdrawals.addNeurons(merge);
        lastHeartbeatMergeDissolving := ?merge;
    };

    // Split off as many staking neurons as we need to satisfy pending withdrawals.
    private func splitNewWithdrawalNeurons() : async () {
        // figure out how much we have dissolving for withdrawals
        let dissolving = withdrawals.totalDissolving();
        let pending = withdrawals.totalPending();

        // Split and dissolve enough new neurons to satisfy pending withdrawals
        lastHeartbeatSplit := if (pending <= dissolving) {
            null
        } else {
            // figure out how much we need dissolving for withdrawals
            let needed = pending - dissolving;
            // Split the difference off from staking neurons
            switch (staking.splitNeurons(needed)) {
                case (#err(err)) {
                    ?#err(err)
                };
                case (#ok(toSplit)) {
                    // Do the splits on the nns and find the new neurons.
                    let newNeurons = Buffer.Buffer<Neurons.Neuron>(toSplit.size());
                    for ((id, amount) in toSplit.vals()) {
                        switch (await neurons.split(id, amount)) {
                            case (#err(err)) {
                                // TODO: Error handling
                            };
                            case (#ok(n)) {
                                newNeurons.add(n);
                            };
                        };
                    };
                    // Pass the new neurons into the withdrawals manager.
                    switch (await dissolveNeurons(newNeurons.toArray())) {
                        case (#err(err)) { ?#err(err) };
                        case (#ok(newNeurons)) { ?#ok(withdrawals.addNeurons(newNeurons)) };
                    }
                };
            }
        };
    };

    private func dissolveNeurons(ns: [Neurons.Neuron]): async Neurons.NeuronsResult {
        let newNeurons = Buffer.Buffer<Neurons.Neuron>(ns.size());
        for (n in ns.vals()) {
            let neuron = switch (n.dissolveState) {
                case (?#DissolveDelaySeconds(delay)) {
                    // Make sure the neuron is dissolving
                    switch (await neurons.dissolve(n.id)) {
                        case (#err(err)) {
                            return #err(err);
                        };
                        case (#ok(n)) {
                            n
                        };
                    }
                };
                case (_) { n };
            };
            newNeurons.add(neuron);
        };
        #ok(newNeurons.toArray())
    };


    // ===== REFERRAL FUNCTIONS =====

    public type ReferralStats = {
        code: Text;
        count: Nat;
        earned: Nat;
    };

    // Get a user's current referral stats. Used for the "Rewards" page.
    public shared(msg) func getReferralStats(): async ReferralStats {
        let code = await referralTracker.getCode(msg.caller);
        let stats = referralTracker.getStats(msg.caller);
        return {
            code = code;
            count = stats.count;
            earned = stats.earned;
        };
    };

    // ===== DEPOSIT FUNCTIONS =====

    // Return the account ID specific to this user's subaccount. This is the
    // address where the user should transfer their deposit ICP.
    public shared(msg) func getDepositAddress(code: ?Text): async Text {
        Debug.print("[Referrals.touch] user: " # debug_show(msg.caller) # ", code: " # debug_show(code));
        referralTracker.touch(msg.caller, code);
        Account.toText(Account.fromPrincipal(Principal.fromActor(this), Account.principalToSubaccount(msg.caller)));
    };

    // Same as getDepositAddress, but allows the canister owner to find it for
    // a specific user.
    public shared(msg) func getDepositAddressFor(user: Principal): async Text {
        owners.require(msg.caller);
        Account.toText(Account.fromPrincipal(Principal.fromActor(this), Account.principalToSubaccount(user)));
    };

    public type DepositErr = {
        #BalanceLow;
        #TransferFailure;
    };

    public type DepositReceipt = {
        #Ok: Nat;
        #Err: DepositErr;
    };

    // After the user transfers their ICP to their depositAddress, process the
    // deposit, be minting the tokens.
    public shared(msg) func depositIcp(): async DepositReceipt {
        await doDepositIcpFor(msg.caller);
    };

    // After the user transfers their ICP to their depositAddress, process the
    // deposit, be minting the tokens.
    public shared(msg) func depositIcpFor(user: Principal): async DepositReceipt {
        owners.require(msg.caller);
        await doDepositIcpFor(user)
    };

    private func doDepositIcpFor(user: Principal): async DepositReceipt {
        // Calculate target subaccount
        let subaccount = Account.principalToSubaccount(user);
        let source_account = Account.fromPrincipal(Principal.fromActor(this), subaccount);

        // Check ledger for value
        let balance = await ledger.account_balance({ account = Blob.toArray(source_account) });

        // Transfer to staking neuron
        if (Nat64.toNat(balance.e8s) <= minimumDeposit) {
            return #Err(#BalanceLow);
        };
        let fee = { e8s = Nat64.fromNat(icpFee) };
        let amount = { e8s = balance.e8s - fee.e8s };
        let icpReceipt = await ledger.transfer({
            memo : Nat64    = 0;
            from_subaccount = ?Blob.toArray(subaccount);
            to              = Blob.toArray(accountIdBlob());
            amount          = amount;
            fee             = fee;
            created_at_time = ?{ timestamp_nanos = Nat64.fromNat(Int.abs(Time.now())) };
        });

        switch icpReceipt {
            case (#Err(_)) {
                return #Err(#TransferFailure);
            };
            case _ {};
        };

        // Mint the new tokens
        Debug.print("[Referrals.convert] user: " # debug_show(user));
        referralTracker.convert(user);
        ignore queueMint(user, amount.e8s);
        ignore flushMint(user);

        return #Ok(Nat64.toNat(amount.e8s));
    };

    // For safety, minting tokens is a two-step process. First we queue them
    // locally, in case the async mint call fails.
    private func queueMint(to : Principal, amount : Nat64) : Nat64 {
        let existing = Option.get(pendingMints.get(to), 0 : Nat64);
        let total = existing + amount;
        pendingMints.put(to, total);
        return total;
    };

    // Execute the pending mints for a specific user on the token canister.
    private func flushMint(to : Principal) : async TxReceipt {
        let total = Option.get(pendingMints.remove(to), 0 : Nat64);
        if (total == 0) {
            return #Err(#AmountTooSmall);
        };
        Debug.print("minting: " # debug_show(total) # " to " # debug_show(to));
        try {
            let result = await token.mint(to, Nat64.toNat(total));
            switch (result) {
                case (#Err(_)) {
                    // Mint failed, revert
                    pendingMints.put(to, total + Option.get(pendingMints.remove(to), 0 : Nat64));
                };
                case _ {};
            };
            result
        } catch (error) {
            // Mint failed, revert
            pendingMints.put(to, total + Option.get(pendingMints.remove(to), 0 : Nat64));
            #Err(#Other(Error.message(error)))
        }
    };

    // Execute all the pending mints on the token canister.
    private func flushAllMints() : async TxReceipt {
        let mints = Iter.toArray(
            Iter.map<(Principal, Nat64), (Principal, Nat)>(pendingMints.entries(), func((to, total)) {
                (to, Nat64.toNat(total))
            })
        );
        for ((to, total) in mints.vals()) {
            Debug.print("minting: " # debug_show(total) # " to " # debug_show(to));
        };
        pendingMints := TrieMap.TrieMap(Principal.equal, Principal.hash);
        try {
            let result = await token.mintAll(mints);
            switch (result) {
                case (#Err(err)) {
                    // Mint failed, revert
                    for ((to, amount) in mints.vals()) {
                        pendingMints.put(to, Nat64.fromNat(amount) + Option.get(pendingMints.get(to), 0 : Nat64));
                    };
                };
                case _ { };
            };
            result
        } catch (error) {
            // Mint failed, revert
            for ((to, amount) in mints.vals()) {
                pendingMints.put(to, Nat64.fromNat(amount) + Option.get(pendingMints.get(to), 0 : Nat64));
            };
            #Err(#Other(Error.message(error)))
        }
    };

    // ===== WITHDRAWAL FUNCTIONS =====

    // Show currently available ICP in this canister. This ICP retained for
    // withdrawals.
    public shared(msg) func availableBalance() : async Nat64 {
        _availableBalance()
    };

    private func _availableBalance() : Nat64 {
        let balance = cachedLedgerBalanceE8s;
        let reserved = withdrawals.reservedIcp();
        if (reserved >= balance) {
            0
        } else {
            balance - reserved
        }
    };

    // Update the canister's cached local balance
    private func refreshAvailableBalance() : async () {
        cachedLedgerBalanceE8s := (await ledger.account_balance({
            account = Blob.toArray(accountIdBlob());
        })).e8s;
    };

    // Datapoints representing available liquidity at a point in time.
    // `[(delay, amount)]`
    public type AvailableLiquidityGraph = [(Int, Nat64)];

    // Generate datapoints for a graph representing how much total liquidity is
    // available over time.
    public shared(msg) func availableLiquidityGraph(): async AvailableLiquidityGraph {
        let neurons = staking.availableLiquidityGraph();
        let b = Buffer.Buffer<(Int, Nat64)>(neurons.size()+1);
        b.add((0, _availableBalance()));
        for ((delay, balance) in neurons.vals()) {
            b.add((delay, balance));
        };
        b.toArray();
    };

    private func availableLiquidity(amount: Nat64): (Int, Nat64) {
        var maxDelay: Int = 0;
        var sum: Nat64 = 0;
        // Is there enough available liquidity in the neurons?
        // Figure out the unstaking schedule
        for ((delay, liquidity) in staking.availableLiquidityGraph().vals()) {
            if (sum >= amount) {
                return (maxDelay, sum);
            };
            sum += Nat64.min(liquidity, amount-sum);
            maxDelay := Int.max(maxDelay, delay);
        };
        return (maxDelay, sum);
    };


    // Create a new withdrawal for a user. This will burn the corresponding
    // amount of tokens, locking them while the withdrawal is pending.
    public shared(msg) func createWithdrawal(user: Principal, total: Nat64) : async Result.Result<Withdrawals.Withdrawal, Withdrawals.WithdrawalsError> {
        if (msg.caller != user) {
            owners.require(msg.caller);
        };

        // Burn the tokens from the user. This makes sure there is enough
        // balance for the user.
        let burn = await token.burnFor(user, Nat64.toNat(total));
        switch (burn) {
            case (#Err(err)) {
                return #err(#TokenError(err));
            };
            case (#Ok(_)) { };
        };

        // Check we have enough cash+neurons
        let availableCash = _availableBalance();
        var delay: Int = 0;
        var availableNeurons: Nat64 = 0;
        if (total > availableCash) {
            let (d, a) = availableLiquidity(total - availableCash);
            delay := d;
            availableNeurons := a;
        };
        if (availableCash+availableNeurons < total) {
            // Refund the user's burnt tokens. In practice, this should never
            // happen, as cash+neurons should be >= totalTokens.
            ignore queueMint(user, total);
            ignore flushMint(user);
            return #err(#InsufficientLiquidity);
        };

        return #ok(withdrawals.createWithdrawal(user, total, availableCash, delay));
    };

    // Complete withdrawal(s), transferring the ready amount to the
    // address/principal of a user's choosing.
    public shared(msg) func completeWithdrawal(user: Principal, amount: Nat64, to: Text): async Withdrawals.PayoutResult {
        if (msg.caller != user) {
            owners.require(msg.caller);
        };

        // See if we got a valid address to send to.
        //
        // Try to parse text as an address or a principal. If a principal, return
        // the default subaccount address for that principal.
        let toAddress = switch (Account.fromText(to)) {
            case (#err(_)) {
                // Try to parse as a principal
                try {
                    Account.fromPrincipal(Principal.fromText(to), Account.defaultSubaccount())
                } catch (error) {
                    return #err(#InvalidAddress);
                };
            };
            case (#ok(toAddress)) {
                if (Account.validateAccountIdentifier(toAddress)) {
                    toAddress
                } else {
                    return #err(#InvalidAddress);
                }
            };
        };

        let (transferArgs, revert) = switch (withdrawals.completeWithdrawal(user, amount, toAddress)) {
            case (#err(err)) { return #err(err); };
            case (#ok(a)) { a };
        };
        try {
            let transfer = await ledger.transfer(transferArgs);
            ignore refreshAvailableBalance();
            switch (transfer) {
                case (#Ok(block)) {
                    #ok(block)
                };
                case (#Err(#InsufficientFunds{})) {
                    // Not enough ICP in the contract
                    revert();
                    #err(#InsufficientLiquidity)
                };
                case (#Err(err)) {
                    revert();
                    #err(#TransferError(err))
                };
            }
        } catch (error) {
            revert();
            #err(#Other(Error.message(error)))
        }
    };

    // List all withdrawals for a user.
    public shared(msg) func listWithdrawals(user: Principal) : async [Withdrawals.Withdrawal] {
        if (msg.caller != user) {
            owners.require(msg.caller);
        };
        return withdrawals.withdrawalsFor(user);
    };

    // ===== HELPER FUNCTIONS =====

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

    public shared(msg) func getAppliedInterestResults(): async [ApplyInterestResult] {
        owners.require(msg.caller);
        return Iter.toArray(appliedInterestEntries.vals());
    };

    public shared(msg) func neuronAccountId(controller: Principal, nonce: Nat64): async Text {
        owners.require(msg.caller);
        return Account.toText(Util.neuronAccountId(args.governance, controller, nonce));
    };

    public shared(msg) func neuronAccountIdSub(controller: Principal, subaccount: Blob.Blob): async Text {
        owners.require(msg.caller);
        return Account.toText(Account.fromPrincipal(args.governance, subaccount));
    };

    // ===== HEARTBEAT FUNCTIONS =====

    private stable var lastHeartbeatAt : Time.Time = if (appliedInterest.size() > 0) {
        appliedInterest.get(appliedInterest.size()-1).timestamp
    } else {
        Time.now()
    };
    private stable var lastHeartbeatError: ?Neurons.NeuronsError = null;
    private stable var lastHeartbeatApply: ?Result.Result<ApplyInterestResult, Neurons.NeuronsError> = null;
    private stable var lastHeartbeatMergeDissolving: ?[Neurons.Neuron] = null;
    private stable var lastHeartbeatFlush: ?[Ledger.TransferArgs] = null;
    private stable var lastHeartbeatRefresh: ?Neurons.NeuronsError = null;
    private stable var lastHeartbeatSplit: ?Neurons.NeuronsResult = null;

    system func heartbeat() : async () {
        ignore refreshAvailableBalance();

        // Execute any pending mints.
        ignore flushAllMints();

        let next = lastHeartbeatAt + day;
        let now = Time.now();
        if (now < next) {
            return;
        };
        // Lock out other calls to this, which might overlap
        lastHeartbeatAt := now;
        try {
            await dailyHeartbeat(?now);
        } catch (error) {
            lastHeartbeatError := ?#Other(Error.message(error));
        };
    };

    // For manual recovery, in case of an issue with the most recent heartbeat.
    public shared(msg) func setLastHeartbeatAt(when: Time.Time): async () {
        owners.require(msg.caller);
        lastHeartbeatAt := when;
    };

    // ===== UPGRADE FUNCTIONS =====

    system func preupgrade() {
        stablePendingMints := ?Iter.toArray(pendingMints.entries());

        // convert the buffer to a stable array
        appliedInterestEntries := appliedInterest.toArray();

        stableReferralData := referralTracker.preupgrade();

        stableNeuronsData := neurons.preupgrade();

        stableStakingData := staking.preupgrade();

        stableWithdrawalsData := withdrawals.preupgrade();

        stableOwners := owners.preupgrade();
    };

    system func postupgrade() {
        switch (stablePendingMints) {
            case (null) {};
            case (?entries) {
                pendingMints := TrieMap.fromEntries<Principal, Nat64>(entries.vals(), Principal.equal, Principal.hash);
                stablePendingMints := null;
            };
        };

        // convert the stable array back to a buffer.
        appliedInterest := Buffer.Buffer(appliedInterestEntries.size());
        for (x in appliedInterestEntries.vals()) {
            appliedInterest.add(x);
        };

        referralTracker.postupgrade(stableReferralData);
        stableReferralData := null;

        neurons.postupgrade(stableNeuronsData);
        stableNeuronsData := null;

        staking.postupgrade(stableStakingData);
        stableStakingData := null;

        withdrawals.postupgrade(stableWithdrawalsData);
        stableWithdrawalsData := null;

        owners.postupgrade(stableOwners);
        stableOwners := null;
    };

};
