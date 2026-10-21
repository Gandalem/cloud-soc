# Work Tracking

- Read `docs/work_tracker.md` before starting project implementation or review.
- Use its task IDs and priority order. A newer explicit user request takes precedence; record any resulting scope or priority change.
- For implementation work, mark the relevant unchecked task as in progress before editing. Keep unrelated tasks unchanged.
- Mark a task `[x]` only after its stated acceptance criteria are met and verified. Record the date, scope, tests/results, relevant files or commit, and remaining limitations in the work log.
- Code completion, isolated tests, deployment, and real-agent ingestion verification are distinct. Never infer deployment or live ingestion from unit tests, a running service, or the presence of source code.
- If only part of a task is complete, leave it unchecked and record what remains. For read-only advice or review, record material decisions when appropriate without marking implementation complete.
- Preserve existing completion history and user changes. Do not record credentials, private keys, or sensitive production logs in the tracker.
- Commit and push only when requested. Updating the tracker does not imply remote deployment.


# Current User Direction (2026-10-21)

- Latest CI scope: Windows passed run39458035104 at216943b; preserve it and do not modify Windows-specific code or rerun Windows. For the follow-up fixed-SQL change, run Ubuntu only via a manual platform choice. Keep normal push/PR checks for both OSes; distinguish the Windows tested SHA from the follow-up Ubuntu SHA.

- Latest user direction: implement CI-BACKUP-REGRESSION-01 with independent legacy fixtures and current format5 coverage. Finish writing before one scoped local review; rerun affected failures only. Commit/push on codex/operational-readiness and inspect PR18 Actions, repairing newly exposed failures in scope. No main merge, deployment, reboot or production data/key changes. This replaces midpoint/final review splitting for this task.

- Latest user direction: implement the TEST-QUALITY-01 draft on codex/operational-readiness, preserving existing edits. Review only new/directly affected tests near 50% and 100%; repair and rerun affected failures. The request to update tests in Git authorizes committing/pushing this change to Gandalem/cloud-soc on the current branch. No main merge, deployment, full suite, live service changes or reboot.

- Latest user direction (2026-10-21): document the remaining dashboard connections and priorities, then commit and push the current development changes to https://github.com/Gandalem/cloud-soc.git on codex/operational-readiness. This supersedes earlier no-commit/no-push directions for this snapshot. Do not merge main, deploy, reboot or run additional feature checks for this documentation/Git request. Preserve historical verification limits and exclude secrets/runtime data from Git.

- Latest user direction: implement the approved dashboard capability draft. Perform exactly two scoped review passes, near 50% and after implementation 100%, limited to major changed code and calculations/state decisions. No full test suite or general browser/E2E/reboot verification. Preserve existing changes; no commit/push.

- Latest user direction: implement dashboard title-area dragging with placement preview plus click-to-place movement. Do not perform any verification, tests, browser checks, lint or syntax checks for this change. Preserve existing layouts and uncommitted changes; record implementation/deployment separately from unverified behavior. No reboot, commit or push.

- Latest user direction: implement the agreed security-focused Windows/Linux/web collection policy and show understandable source/event types in unified logs. Do not run intermediate tests, lint, builds or execution checks; finish implementation first and then perform consolidated final review and affected repairs. Do not reboot or perform reboot validation for this task. Preserve existing changes, data, keys, evidence and checkpoints; no commit/push. Current lab deployment is authorized; other live endpoints require separate scope confirmation.
- Latest user direction: implement the agreed continuous ingestion/detection and shared AJAX draft; do not run intermediate tests, lint, builds or execution checks. Complete implementation first, then perform one consolidated final review, repair/recheck affected failures, and only after that reboot the current lab VM and verify the full flow. Lab service deployment/startup configuration is explicitly in scope; production remains excluded. Preserve existing state, data, keys and uncommitted changes; no commit/push.
- Develop on Gandalem/cloud-soc codex/operational-readiness (user direction updated 2026-10-20). Implement the agreed form-based rule-management and fast-detection draft while preserving the collection-to-alert goal. Do not confuse the current work/cloud-soc-main directory name with its active branch or modify the separate D:/cloud-soc checkout.
- User direction updated 2026-10-20: implement the agreed rule-management draft. Review in two consolidated passes: near the implementation midpoint and after completion. Run relevant checks in those passes; rerun only affected failures after a correction. Do not repeatedly run broad suites. Production/service changes remain excluded.
- Keep implementation and verification distinct. Record unverified changes honestly and leave unverified acceptance items unchecked.
- The earlier commercial-foundation snapshot is archived in Gandalem/test-cs; do not automatically apply it to this main checkout.
- Product pages must not include developer progress commentary such as verification promises, planned testing, unfinished/MVP labels, or implementation-completion disclaimers. Keep development scope, verification status, and remaining work in project documents and the work tracker. UI text should describe user actions and actual results; do not claim an operation succeeded or was applied when it did not.


# Current local integration request (2026-10-21)

- Compare and merge main + JEONGRIM-SEO locally; this current user request supersedes historical branch and verification restrictions above for this integration.
- Validate the merged code locally. The latest user request explicitly authorizes committing the reviewed integration and pushing it to JEONGRIM-SEO. Do not push main, create remote PRs, deploy, or change existing services.


# Current AWS Sydney request (2026-10-21)

- Implement and locally validate Sydney AWS/T-Pot ingestion and connect approved existing AWS resources. The user selected code/local verification and existing-resource connection, not new cloud provisioning.
- Same account, separate team IAM Roles; T-Pot is not installed yet. Read-only AWS inventory and bounded existing-log metadata sampling are authorized.
- Do not repurpose the existing CI runner or enable new AWS resources, costs, public honeypot ports or role grants without a concrete approved scope. Do not automatically commit/push this new task based on the earlier merge-only push authorization.


# Latest AWS provisioning authorization (2026-10-21)

- The user explicitly approved creating one private Sydney S3 bucket and SQS plus DLQ, enabling VPC Flow/ALB access logging, and subsequently requested Sydney CloudTrail storage. This supersedes the earlier existing-resources-only limit for those actions.
- The user will create the new EC2 instance. Do not repurpose the CI runner, create IAM identity grants/instance roles, or expose ports based only on the reference conversation.
- Implement web collection for ZIYA0614/security-mall. Apply the shared conversation requirements for four distinct IAM users, at least three app pages, and CloudWatch web collection; use Sydney instead of its Seoul example.

2026-10-21 추가 사용자 승인: ALB 전달 조건을 같은 계정·시드니 loadbalancer/*로 수정, 새 EC2의 default VPC Flow 추가, CloudSOC-SecurityMall-Sydney 전용 EC2 역할 및 지정 CloudWatch 쓰기+AmazonSSMManagedInstanceCore 연결, 고정 Security Mall 설치·실행 허용. 공개 포트 추가와 기존 Trail 변경은 포함하지 않음.

2026-10-21 최신 사용자 지시: 현재 AWS Sydney·Security Mall 변경을 JEONGRIM-SEO에 commit 및 push한다. 이전 미커밋/미push 지시를 이번 변경에 한해 대체한다. main은 변경하지 않는다.
