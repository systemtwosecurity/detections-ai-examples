# Open a detection in Defender Advanced Hunting

`open_in_advanced_hunting.py` turns a KQL query into a Microsoft Defender XDR Advanced Hunting link. Opening the link
loads the query into the console editor, ready to run.

Use it when the detections.ai MCP server is the only tool connected to your AI assistant. The assistant finds and tunes
detections through the MCP server, and you run each query against your own data in Defender. Your assistant never needs
Defender or Sentinel credentials.

## Requirements

- Python 3.9 or later. The script uses only the standard library.
- An account that can open Advanced Hunting at [security.microsoft.com](https://security.microsoft.com).

## Usage

```bash
# From a file
python3 open_in_advanced_hunting.py query.kql

# From stdin, opening the link in your default browser
pbpaste | python3 open_in_advanced_hunting.py --open

# From an argument
python3 open_in_advanced_hunting.py --query 'DeviceProcessEvents | take 10'
```

The script prints the link. It opens Advanced Hunting with the time range set to **Last 24 hours**.

| Option         | What it does                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------ |
| `--open`       | Opens the link in your default browser as well as printing it.                                   |
| `--time-range` | Sets the console's `timeRangeId`. The default, `day`, is Last 24 hours. Other values are untested. |
| `--tenant`     | Adds `tid=<tenant ID>`. Untested. Without it, the console opens in the tenant you used last.     |

If the link would be longer than 8,000 characters, the script prints no link and exits with code 2, because browsers and
proxies can cut off longer URLs. Paste that query into the console yourself.

## Install it as an agent skill

This folder is also an agent skill: [SKILL.md](SKILL.md) tells your assistant to build links with this script instead
of by hand. Copy the folder into your skills directory:

```bash
# Claude Code (all projects)
cp -r defender/open-in-advanced-hunting ~/.claude/skills/

# Claude Code (one project)
cp -r defender/open-in-advanced-hunting <project>/.claude/skills/
```

Other assistants that read `SKILL.md` files, such as Codex, take the same folder in their own skills directory. Then
ask for "a link to run this detection in Defender".

## With the detections.ai MCP server

1. Ask your assistant to find a hunt package (`search_hunt_packages`) and pick one of its detections.
2. Ask for the detection's KQL (`get_detections`). A Sigma rule isn't a hunting query, so ask the assistant to translate it
   to Defender KQL first.
3. Save the query to `query.kql` and run `python3 open_in_advanced_hunting.py query.kql --open`.
4. Run the query in Defender, then type a summary of the results into the chat: the hit count, the top values of the
   columns that identify who or what fired it, and which rows look benign. Your assistant can't see Defender, so it works
   only from what you write.
5. Ask the assistant to tune the detection (`customize_detection`), then open the tuned query the same way.

## How the link works

Microsoft doesn't document this link format. The script UTF-16LE-encodes the query, gzips it, base64-encodes it and
percent-encodes the result into the `query` parameter. A UTF-8 payload loads as CJK characters.
`test_open_in_advanced_hunting.py` decodes a built link and checks that it gives back the original query, so a change to
the encoding fails the test:

```bash
python3 -m unittest -v
```

If Microsoft changes the format, the link opens with an empty or garbled editor. Paste the query in by hand and
[open an issue](../../CONTRIBUTING.md#reporting-a-problem).
