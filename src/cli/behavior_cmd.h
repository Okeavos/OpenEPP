#pragma once

// sec-cli behavior-replay <file|-> [--rules <file>] [--ioc <file>] [--json]
// sec-cli behavior-rules
int run_behavior_replay(int argc, char** argv, int from);
int run_behavior_rules();
