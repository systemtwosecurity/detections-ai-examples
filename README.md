# detections.ai examples

Working examples that connect detections.ai to other tools through the
[public API](https://detections.ai/api/v1-beta/docs) and its webhooks.

## Azure Logic Apps

- [Nightwatch finding to Microsoft Defender alert](logic-apps/nightwatch-finding-to-defender-alert/): raises a Microsoft
  Defender XDR alert for each new Nightwatch finding.

## Agent skills

- [Open a detection in Defender Advanced Hunting](skills/open-in-defender-advanced-hunting/): turns a KQL query into a
  link that loads it into the Advanced Hunting editor, so you can run detections.ai queries against your own data.

## License

[MIT](LICENSE)
