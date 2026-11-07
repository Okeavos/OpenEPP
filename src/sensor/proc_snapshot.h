#pragma once

#include "behavior/event.h"

#include <vector>

namespace sec::sensor {

// Processes that are running right now. macOS: libproc for path/ppid/argv and the Security framework
// for signing information (needs root to read other users' argv and environment). Elsewhere a /proc
// based version is used (no signing information); it exists mainly so the code path can be tested.
//
// Used once at sensor start-up so the engine knows the signing state and ancestry of processes that
// were launched before the sensor.
std::vector<behavior::ProcessRef> snapshot_processes();

}
