# Cyber Shield Browser Extension

This Manifest V3 extension provides a defensive one-click workflow for sending the active web page to Cyber Shield AI for analysis.

## Installation

1. Open `chrome://extensions/` (or the equivalent extensions page in Edge or Brave).
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select the `extension` folder.
4. Open the Cyber Shield AI extension and choose **Configuration**.
5. Enter the HTTPS origin of your Cyber Shield API gateway, for example `https://your-app.example`.
6. Save the configuration and return to the analysis view.

The extension intentionally requires an HTTPS API origin and rejects embedded credentials, query strings, and fragments in the configured gateway URL.

## Usage

Open an HTTP(S) page, click the Cyber Shield AI toolbar action, and choose **Analyze current page**. The extension sends only the active page URL to `POST /api/analyze` and displays the normalized threat classification, score, indicator count, TLS signal, and recommendation.

## Security

The extension uses Manifest V3, a restrictive extension-page CSP, and no wildcard host permission. The repository includes an extension packaging smoke test that validates both the source and published copies.
