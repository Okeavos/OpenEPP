#pragma once

#include "behavior/engine.h"
#include "scanner/scan_engine.h"

namespace sec::sensor {

// Looks at the files an alert points to (Alert::suspect_paths), hashes them and runs the file scanner
// over them, and records the result in Alert::files. A file the scanner calls malicious raises the
// alert to critical. Safe to call from one thread at a time; `engine` must outlive the enricher.
class AlertEnricher {
public:
    explicit AlertEnricher(const ScanEngine* engine) : engine_(engine) {}

    void operator()(behavior::Alert& a) const;

    // "path  sha256:...  12.3 KB  verdict" (also used by tests).
    static std::string describe(const ScanResult& r);

private:
    const ScanEngine* engine_;
};

}
