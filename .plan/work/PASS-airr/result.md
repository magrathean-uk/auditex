## RESULT PASS-airr
status: done
summary: Both systems can run 8B to 27B LoRA jobs, with caveats. Isambard-AI is Arm64 (Grace) with H100 GPUs, so it needs aarch64 wheels, conda or NGC containers, and builds on compute nodes. Dawn is x86-64 with Intel Max 1550 GPUs, and its PyTorch route uses an Intel extension that Intel has discontinued.
summary: Confidence is medium. Egress rules, compute-node internet access, and PEFT and bitsandbytes support were not found in any source.
changes: none
verification: 7 WebSearch and 11 WebFetch used (search budget 8). No repo files edited, no code run. Quotes come from fetch summaries, so check the page for exact wording.
risks: Most Isambard and Dawn pages are undated, so versions may be stale. Dawn's 36 h limit is marked provisional. Model-weight download rules are unsourced.
questions_for_g: none

### Findings

Direct answer:
1. Isambard-AI (Bristol): Arm64 Grace CPUs with H100 GH200 GPUs, 4 per node. PyTorch and Hugging Face have pip, conda or container routes. TensorFlow and Flash-Attention need conda or a container.
2. Dawn (Cambridge): x86-64 Sapphire Rapids with Intel Max 1550 GPUs, 4 per node. PyTorch runs in a `pytorch-gpu` conda env on the Intel extension.
3. Both: Slurm, budgets in GPU-hours or NHR. Apptainer is documented only for Isambard-AI. No egress rules found for either.

Isambard-AI
1. Each node has 4 GH200 superchips (72-core Grace, H100 96 GB); CPUs are aarch64. Source: https://docs.isambard.ac.uk/user-documentation/information/how-isambard-works/ (undated). Quote: "CPUs are ARM (aarch64)."
2. x86_64 binaries, Conda environments and most public Docker images will not run on the ARM nodes. Same source. Quote: "will not run on the ARM nodes."
3. Support matrix (aarch64): PyTorch pip, conda, container. Hugging Face pip, conda, container. vLLM pip, container. JAX pip, container. Flash-Attention conda, container. TensorFlow container only. Source: https://docs.isambard.ac.uk/user-documentation/applications/ML-packages/ (undated; cites PyTorch 2.6 and vLLM 0.10.2). The same page also says "We do not plan to provide pip wheels", which conflicts with the pip ticks. Verify on the system.
4. Install on compute nodes, because login nodes have no GPUs (e.g. `srun --nodes=1 --gpus=4 --pty bash`). Build Flash-Attention on compute nodes, or set `MAX_JOBS=2` on login. Same ML page.
5. PEFT, bitsandbytes and transformers builds on aarch64: no source found. Unverified.
6. Scheduler: default `workq` has 24 h max walltime on Phase 1 and Phase 2. Phase 2 `interactive` reservation: 8 h max, 30 min default, up to 4 nodes (16 GPUs), billed at 1.5x. Source: https://docs.isambard.ac.uk/user-documentation/information/job-scheduling (undated; table text is fragmentary).
7. Per-project cap of 32 GPUs (`32gpu_qos`). Per user, `workq` allows 256 running and 512 pending plus running jobs. Phase not stated. Same source.
8. Budget: 1 NHR is one node-hour, so 1 GPU-hour is 0.25 NHR. Jobs will not start without enough NHR. Running jobs are not killed. Unused NHR is lost at project end. Source: how-isambard-works (above).
9. Containers: Apptainer on login and compute nodes (`apptainer` on Phase 2). Pulls via `docker://` from Docker Hub and Quay. `--nv` for GPUs. `$HOME` bound by default. `--fakeroot` for builds. Docker is unavailable. Source: https://docs.isambard.ac.uk/user-documentation/guides/containers/apptainer/ (undated).
10. Storage: `$HOME` 100 GiB; `$PROJECTDIR` 200 TiB per project, shared; `$SCRATCHDIR` 5 TiB per user. Nothing is backed up. Source: how-isambard-works. Phase 1 and Phase 2 have separate storage. Source: https://docs.isambard.ac.uk/user-documentation/faqs (undated).
11. Transfer: scp or rsync to login nodes. Large transfers should run as Slurm jobs, because login nodes are shared and resource-limited. Source: FAQ (above). No egress pricing found.
12. Access: only PIs invite users, and accounts need institutional email. Storage quotas are agreed with the allocator, and BriCS cannot raise them. Budgets are pre-allocated, not pay-as-you-go. Sources: FAQ and how-isambard-works.
13. Model weights: the FAQ says Hugging Face rate-limits unauthenticated traffic per IP, so authenticate with `uvx hf auth login`. No official rule on compute-node internet access was found. A third-party gist (https://gist.github.com/muhark) says compute nodes are offline and `/home` is 10 GB. Unverified.

Dawn
14. Hardware: 256 Dell XE9640 nodes. Each has 2x Xeon Platinum 8468 (96 cores), 1024 GiB RAM, and 4x Intel Max 1550 (128 GiB each), with Xe-Link within the node and HDR200 InfiniBand between nodes. Source: https://docs.hpc.cam.ac.uk/user-guide/pvc.html (undated; "Early Access" from January 2024). Quote: "Xe-Link 4-way GPU interconnect within the node."
15. Modules: `module purge`, then `module load rhel9/default-dawn`. Rebuild software on Dawn nodes. Intel oneAPI, Intel MPI and oneMKL are available. Source: https://docs.hpc.cam.ac.uk/user-guide/pvc-jobs.html (undated).
16. Slurm: partition `pvc9` (`pvc-s-[1-256]`); 24 CPUs per GPU enforced; `--gres=gpu:N`. Accounts are `NAME-DAWN-GPU`, charged in GPU-hours. Per user: 64 GPUs and 36 h per job, marked "provisional". Same pvc-jobs page.
17. PyTorch: `module load intelpython-conda`, then `conda activate pytorch-gpu`. GPU support is via Intel Extension for PyTorch. Source: https://docs.hpc.cam.ac.uk/user-guide/pvc-jobs-ML.html (undated; no version stated).
18. Conflict: Intel's release notes say active development of the extension stops after 2.8, and recommend PyTorch's own allocator. Source: https://intel.github.io/intel-extension-for-pytorch/xpu/latest/tutorials/releases.html (undated). Intel is more authoritative on its own extension's status. Check the env with `conda list`.
19. Access: MyAccessID login, with Waldur for authorisation and allocations. UK university PIs apply to UKRI/DSIT, and projects are assigned to Cambridge or Bristol. Source: pvc.html (above).
20. Not found for Dawn: container support, storage quotas, transfer or egress rules, and model-weight guidance.

AIRR routes and systems
21. UKRI Rapid Access (updated 15 Oct 2026): 20,000 GPU-hours, used within three months of award, for UK micro, small and medium businesses, with no funding. Source: https://www.ukri.org/opportunity/isambard-ai-and-dawn-airr-supercomputers-rapid-access-route/
22. gov.uk AIRR page (updated 28 Sep 2026): Rapid Access 20,000 GPU-hours, Gateway 10,000, Innovator closed 16 Jan 2026. Isambard-AI 5,448 GH200; Dawn 1,024 GPUs. Source: https://www.gov.uk/government/publications/ai-research-resource/airr-advanced-supercomputers-for-the-uk
23. Source conflict: an older UKRI listing says Rapid Access covers Dawn or Isambard-AI and Innovator is open at 50k to 150k GPU-hours. The newer pages supersede it. The gov.uk and October 2026 UKRI pages are more authoritative. Also, job-scheduling gives 5,432 GPUs (38 + 1,320 nodes x 4) against gov.uk's 5,448. Unexplained.

Open points
- Egress pricing and compute-node internet access: ask Isambard support or the allocator.
- PEFT, transformers and bitsandbytes on aarch64 and XPU: no source found.
- Dawn containers, storage quotas and transfer rules: not sourced.
- Dawn login-node details come from a search snippet only, not a fetched page.
