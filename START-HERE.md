# Mobiledestro v1

By **Nipun Dilshan Seneviurathne**.

1. [Detailed manual](Mobiledestro-v1/docs/MOBILEDESTRO-V1-MANUAL.md).
2. [GitHub-ready source folder](Mobiledestro-v1/README.md).
3. [Full repository ZIP](Mobiledestro-v1-full.zip).
4. [Installable skill ZIP](Mobiledestro-v1-skill.zip).
5. [Validation and limitations](Mobiledestro-v1/docs/VALIDATION.md).
6. [Archive SHA-256 checksums](SHA256SUMS.txt).

From the source folder, run `python tools/install_skill.py --project /path/to/assessment-project`, then invoke `/mobiledestro-v1` in Claude Code. For a personal installation use `--personal` instead. Manual installation: extract the skill ZIP so its `mobiledestro-v1` folder sits inside the chosen `.claude/skills` directory.

The release contains ten research modules, tested offline helpers, evidence-driven chain procedures, reporting templates, regression tests, research references and the attributed original Mobilehunter archive. Active Android testing uses your installed tools and authorized lab.

Validation: 66 tests passed, one filesystem-symlink test skipped, and a synthetic end-to-end demo completed. A live Claude Code or Android target session was not available for validation. No tool can guarantee finding every vulnerability; comparative superiority has not been benchmarked.
