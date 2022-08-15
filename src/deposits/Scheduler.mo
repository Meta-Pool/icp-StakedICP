import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Error "mo:base/Error";
import Int "mo:base/Int";
import Iter "mo:base/Iter";
import Option "mo:base/Option";
import P "mo:base/Prelude";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import TrieMap "mo:base/TrieMap";

module {
    public type UpgradeData = {
        #v1: {
            lastJobResults: [(Text, JobResult)];
        };
    };

    public type JobMetrics = {
        startedAt: Time.Time;
        completedAt: ?Time.Time;
        ok: Bool;
    };

    public type Metrics = {
        jobs: [JobMetrics];
    };

    public type Job = {
        name : Text;
        interval : Int;
        function : (now: Time.Time) -> async Result.Result<Any, Any>;
    };

    public type JobResult = {
        startedAt : Time.Time;
        completedAt : ?Time.Time;
        result : ?Result.Result<Any, Any>;
    };

    // Scheduler manages regularly performed background jobs
    public class Scheduler() {
        // Makes date math simpler
        let second : Int = 1_000_000_000;
        let minute : Int = 60 * second;
        let hour : Int = 60 * minute;
        let day : Int = 24 * hour;

        let defaultJobResult : JobResult = {
            startedAt = 0;
            completedAt = null;
            result = null;
        };

        private var lastJobResults = TrieMap.TrieMap<Text, JobResult>(Text.equal, Text.hash);

        // ===== METRICS FUNCTIONS =====

        // Expose metrics to track canister performance, and behaviour. These are
        // ingested and served by the "metrics" canister.
        public func metrics() : Metrics {
            let ms = Buffer.Buffer<JobMetrics>(lastJobResults.size());
            for ((name, {startedAt; completedAt; result}) in lastJobResults.entries()) {
                ms.add({
                    startedAt = startedAt;
                    completedAt = completedAt;
                    ok = switch (result) {
                        case (?#ok(_)) { true };
                        case (_) { false };
                    };
                });
            };
            return { jobs = ms.toArray() };
        };

        // ===== GETTER/SETTER FUNCTIONS =====

        // For manual recovery, in case of an issue with the most recent heartbeat.
        public func getLastJobResult(name: Text): ?JobResult {
            lastJobResults.get(name)
        };

        // For manual recovery, in case of an issue with the most recent heartbeat.
        public func setLastJobResult(name: Text, r: JobResult): () {
            lastJobResults.put(name, r);
        };

        // ===== HEARTBEAT FUNCTIONS =====

        // Try to run all scheduled jobs. This should be called in the
        // heartbeat function of the importing canister. Most of the time it
        // will be a no-op.
        public func heartbeat(now: Time.Time, jobs: [Job]) : async () {
            let jobsToRun = Array.filter(jobs, func({name; interval}: Job): Bool {
                switch (lastJobResults.get(name)) {
                    case (?{startedAt; completedAt}) {
                        if (completedAt == null) {
                            // Currently running
                            return false;
                        };
                        let next = startedAt + interval;
                        if (now < next) {
                            // Not scheduled yet
                            return false;
                        };
                    };
                    case (_) { };
                };
                return true;
            });

            // Set all jobs as "currently running", to lock out other calls to this, which might overlap
            for ({name} in jobsToRun.vals()) {
                lastJobResults.put(name, {
                    startedAt = now;
                    completedAt = null;
                    result = null;
                });
            };

            // Start all jobs
            for (j in jobsToRun.vals()) {
                ignore runJob(j, now)
            };
        };

        // Asynchronously run a job and store the result
        func runJob({name; interval; function}: Job, now: Time.Time): async () {
            try {
                let result = await function(now);
                lastJobResults.put(name, {
                    startedAt = now;
                    completedAt = ?Time.now();
                    result = ?result;
                });
            } catch (error) {
                lastJobResults.put(name, {
                    startedAt = now;
                    completedAt = ?Time.now();
                    result = ?#err(#Other(Error.message(error)));
                });
            };
        };

        // ===== UPGRADE FUNCTIONS =====

        public func preupgrade() : ?UpgradeData {
            return ?#v1({
                lastJobResults = Iter.toArray(lastJobResults.entries());
            });
        };

        public func postupgrade(upgradeData : ?UpgradeData) {
            switch (upgradeData) {
                case (?#v1(data)) {
                    lastJobResults := TrieMap.fromEntries(
                        data.lastJobResults.vals(),
                        Text.equal,
                        Text.hash
                    );
                };
                case (_) { return; }
            };
        };
    };
};
