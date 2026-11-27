#!/bin/sh
# Superseded recovery script. The old READY queue pass could choose the wrong
# source generation while a distinct signed generation owns Pending SQL.
# The correct workflow MUST select that exact generation-id explicitly.
echo "FI C1 STOP: this READY-selected recovery script is superseded." >&2
echo "Use fi_c1_c220_resume_exact_pending.sh --resume-and-drain" >&2
exit 1
