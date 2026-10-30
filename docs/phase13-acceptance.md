# Phase 13 frontend acceptance

## Automated checks

From the repository root:

```powershell
cd frontend
npm test
npm run build
```

The comparison tests cover alternating pair order, warm-up marking, empty and populated statistics, exclusion of warm-ups, history medians, latest completed-run selection, and audit event labels.

## Analyst UI checks

1. Log in as an analyst and open **Secure vs Unsecured**. Confirm the amber warning states that plaintext is sent and advises synthetic data.
2. Use a short synthetic message, 3 warm-up pairs, and 5 measured pairs. Start a run. Confirm progress advances by measured pairs and that order alternates secure-first/plain-first.
3. In browser DevTools, inspect POST/GET bodies. Secured POSTs contain an encrypted envelope and signature, unsecured POSTs contain the exact plaintext. No private key, DH shared secret, HKDF output, or AES/HMAC key is uploaded.
4. Confirm secured retrieval checks envelope format/replay, HMAC, signature, then decrypts; successful round trips show all checks passing. Compare the secured and unsecured returned message in the browser.
5. Confirm warm-ups are absent from the finalized timing table, and the run displays setup timings, total/segment timings, body-byte sizes, means, medians, and p95 values.
6. Select **Stop after current pair** during a longer run. Confirm the current pair completes, the run is saved as stopped, and only fully completed measured pairs appear in the results.
7. Open **Stored Data** and expand an exchange. Secured previews must display ciphertext/tag/signature hex previews rather than full ciphertext by default; unsecured exchange text is visibly plaintext. Confirm deletion works for one run and for all runs.
8. Open **History**. Confirm completed/stopped runs show secure and unsecured medians and can be selected to inspect stored results.
9. Start another run, then navigate away from the dashboard tab. Confirm the in-flight request is aborted and the run is not displayed as completed.
10. Repeat with UTF-8 text (emoji and accented characters) and confirm input bytes and transport body-byte counts reflect UTF-8 encoding.

## Interpretation and limitations

The comparison is an educational browser-to-server loopback measurement, not a universal algorithm speed claim. It includes browser work and HTTP round trips. Hardware, timer precision, network conditions, browser scheduling, and server load affect results. HTTP headers are excluded from the body-byte totals. Run several trials and compare medians; do not treat client-reported metrics as tamper-proof evidence.

Run only with synthetic content. The run record and unsecured message are intentionally persisted for analyst review. Clear comparison data after a demonstration if retention is not wanted. A plaintext PCAP is expected to reveal the unsecured message; secured payloads should show ciphertext and metadata rather than the message body.
