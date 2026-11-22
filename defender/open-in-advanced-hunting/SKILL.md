---
name: open-in-advanced-hunting
description: Build a Microsoft Defender Advanced Hunting link that loads a KQL query into the console editor, ready to run. Use when the user asks for a link to run a detection, rule or query in Defender, asks to open a query in Defender or Advanced Hunting, or wants to try a detections.ai detection against their own Defender or Sentinel data.
---

# Open a query in Defender Advanced Hunting

You can't see the user's Defender data. This skill gives them a link that opens the query in Advanced Hunting, where
they run it. They then type a summary of the results back to you.

## Steps

1. Get the query text. For a detections.ai detection, read its rule body with `get_detections`. Use Defender Advanced
   Hunting KQL only: if the rule is Sigma or another language, translate it to KQL first and show the translation.
2. Write the KQL exactly as it should run to `query.kql`. Don't add a time filter: the link sets the time range.
3. Build the link with `open_in_advanced_hunting.py` from this skill's base directory. Never build the link by hand:
   the encoding is undocumented and easy to get wrong.

   ```bash
   python3 <skill base directory>/open_in_advanced_hunting.py query.kql
   ```

   - Add `--open` if the user asks you to open it.
   - Don't pass `--tenant` or `--time-range` unless the user asks: both are untested.

4. Give the user the link the script printed, unchanged, plus one line saying what the query looks for.
5. If the script exits with code 2, the link would be too long. Say so, and give the KQL in a code block to paste into
   Advanced Hunting.
6. If you can't run commands, give the user the contents of `query.kql` and the command from step 3 to run themselves.

## After the user runs it

The user types a summary of what Defender returned: the hit count, the top values of the columns that identify who or
what fired it, and which rows look benign. Work only from that summary. Never invent rows, counts or values.

To tune the query from the summary, use `customize_detection` (or `revise_detection_customization` for a further
round), then repeat the steps above for the tuned query.
