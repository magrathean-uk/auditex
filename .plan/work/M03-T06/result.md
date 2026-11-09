## RESULT M03-T06
status: done
summary: published-artefacts: verified
published-artefacts: verified
summary: Both v1.3.0 assets downloaded fresh into a new folder under $TMPDIR; sha256 matches the DEC-019 record exactly for the wheel and the sdist.
summary: The wheel installed in a throwaway venv under $TMPDIR (Python 3.14.7); `auditex --version` and package metadata both report 1.3.0.
summary: Evidence in .plan/work/M03-T06/evidence.md; result.md carries the verified line.
changes: none in the repository; wrote .plan/work/M03-T06/result.md and evidence.md in the main checkout's work directory
verification: gh release download v1.3.0 - pass; shasum -a 256 wheel and sdist - pass (both match); venv pip install of wheel - pass; auditex --version prints 1.3.0 - pass; grep -qx 'published-artefacts: verified' result.md - pass
risks: none
questions_for_g: none
