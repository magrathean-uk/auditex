## RESULT M07-T07
status: done
summary: None of the four additions trips a kit guard, in the dry run or the real run. None changes what 10 creates or what -Enforce does, changes an expected verdict, or touches a rollback step or MANUAL stop. Nothing in the kit reads devices or device compliance, Graph application permissions, or groups and licences outside the kit's own. No kit source change is needed. Two operator checks matter: which method the lock-out guard counts for the operator, and removing the additions by hand at trial end, because rollback never undoes them.
changes: .plan/work/M07-T07/notes.md only; kit untouched
verification: grep, sed and a Python JSON read of kit-ro only; no PowerShell, no sign-in, no tenant contact, no network
risks: The lock-out guard counts any Windows Hello key the operator has registered as phishing-resistant, whatever device it is on; a key registered inside a Cloud PC can only be used inside that Cloud PC, which itself sits behind 3.6. A later role given to the service principal or to a Windows 365 service principal would change 7.1, 7.2, 7.4 and 7.5; a group holding a role makes them UNKNOWN. LIMITS.md:160 still says "No enrolled device exists" (docs only).
questions_for_g: none
### Findings
1. Counts and guards
- Size guard (kit-ro/populate/_common.ps1:3178-3187) counts only member users, limit 60, and only under -Apply. None of the four additions adds a user. No "tenant must be empty" check exists.
- Licence audit (_common.ps1:1805-1839) judges only a SKU that carries a needed plan (:1831). A Windows 365 SKU carries none, so it is printed (00-identity.ps1:140-149) and skipped. Every SKU's skuId, skuPartNumber and servicePlanName are read strictly (00:151-152,173-176; 90-verify.ps1:239-241).
- Seats (00:156-163,182-198): only the configured SKU and the 16 kit users count, so Windows 365 seats cost nothing. If the Global Reader was also given an E5 seat, that is one seat fewer; 25 covers it. The dry run shows MANUAL at 00:194-197, while -Apply throws.
- Groups: 00 reads only the four DT names and throws only on duplicates of those (00:79,92-98,204-205). 10 reads only the break-glass group (10:68-70,207-222). The operator's licences are never read (00:178-179). The GA total (00:224-225,384-385) is unchanged.
2. Conditional Access
- Policies at 10:111-142. The only exclusion is the break-glass group (10:107). 3.6 targets the eight role ids (_common.ps1:3160-3169; Global Reader is not one). 3.7 covers eng4 only (10:126-129). 3.8 stays report-only (10:130-132).
- What 10 creates and what -Enforce does depend only on constants and the IDs of the break-glass group and eng4. Windows 365 creates no CA policy (non-DT policies are listed at 10:73-101).
- No device or compliance read anywhere: no /devices, deviceManagement or managedDevices call; TRIAL-FACTS.md:42; tools/rego-dependencies.json has no device key.
- 3.7 is not met because the scope is one user (90-verify.ps1:301). 3.8 is not met because it is report-only (90-verify.ps1:302). See EXPECTED-VERDICTS.json:366,402. Two compliant devices change neither verdict.
- Lock-out guard: transitiveMemberOf (10:151) only matters if the FIDO2 or X509 method config targets the new group. The guard counts any Windows Hello key regardless of device (10:55-59,180-188) and prints the method it counted (10:224).
3. Verify and compare
- 7.x rows count only principals holding the eight roles as directory roles (90-verify.ps1:475-492; a group holder throws at :488). Application permissions are never read.
- 5.1, 5.2, 5.3 and 5.5-5.7 read policies and classifications (90-verify.ps1:348-453), not app registrations or what a service principal has been granted.
- P2 count (90-verify.ps1:237-246): unchanged. service_plans was already blocked in Auditex (LIMITS.md:30). SECURITYSUITE 3.2 stays not met (LIMITS.md:161).
- compare.py has no device, group or principal count logic (compare.py:77-78).
- Could change an expected result: none of the four as they stand.
- Cannot: the new group (no role, no CA reference); the provisioning policy (no CA policy); the licences and devices (other SKU, no row reads devices); the service principal (no directory role; app permissions are never read).
4. Rollback
- The CA gate reads DT policies only (99-rollback.ps1:658-690).
- Users: the operator is refused by UPN and by id (99:322-336).
- Licences: only the configured SKU is removed from kit users (00:282; 99:520-527).
- Groups and members are matched by journalled id (99:319-321,508-511). PIM: MANUAL only for the same principal and role (99:241-268). 99 has no size guard.
- None of the four is journalled, so rollback leaves them all in place.
Operator checks and actions (no kit source change)
1. In the 10 dry run, the operator's guard line must say "via fido2" and not "windowsHelloForBusiness". Keep the operator's passkey usable from the Mac.
2. Keep the new group out of the FIDO2 and X509 method targets, and out of every CA exclusion.
3. Before steps 9 and 11, read the holders of the eight privileged roles after the Cloud PCs are provisioned. Expect only the T03 set; the service principal must hold no role.
4. Read the 00 dry-run seat line ("c of p used, f free") and confirm at least 16 seats are free.
5. After -Enforce, test the operator's Cloud PC connection: 3.6 now requires a phishing-resistant method for it.
6. At trial end, remove the Cloud PCs, licences, provisioning policy and group by hand, and turn off billing on any Windows 365 trial.
Kit source changes (each reopens the offline gate)
1. None needed.
2. Optional, docs only: update LIMITS.md:160.
3. Out of scope: making 3.7 and 3.8 met (all-users scope plus enforcement) is a blueprint change for a later round.
