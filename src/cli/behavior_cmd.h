#pragma once

// sec-cli behavior-replay <file|-> [--rules <file>] [--ioc <file>] [--json] [--no-inspect]
// sec-cli behavior-rules
int run_behavior_replay(int argc, char** argv, int from);
int run_behavior_rules();
// sec-cli behavior-bench [--processes N] [--seed S]
int run_behavior_bench(int argc, char** argv, int from);
