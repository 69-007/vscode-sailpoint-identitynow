# AVA SOC PORTAL V6 SAFE

`scripts/ava-soc-portal-v6-safe.ps1`

## Eigenschaften

- Lokal, defensiv, read-only
- Erstellt Snapshot, Analyse und HTML-Portal
- Baseline/Delta-Erkennung über gespeicherten Zustand
- Timeline-, Alert- und Tangle-Logs als JSONL

## Ausführung

```powershell
.\scripts\ava-soc-portal-v6-safe.ps1

# Optional eigener Basisordner
.\scripts\ava-soc-portal-v6-safe.ps1 -OutputDirectory "C:\Security\AVA"
```

## Ausgabeorte

- `<OutputBase>\AVA_SOC_PORTAL_V6_SAFE\Reports\snapshot_latest.json`
- `<OutputBase>\AVA_SOC_PORTAL_V6_SAFE\Reports\analysis_latest.json`
- `<OutputBase>\AVA_SOC_PORTAL_V6_SAFE\Reports\ava_soc_portal_v6_safe.html`

`<OutputBase>` ist `-OutputDirectory`, sonst Desktop (mit Temp-Fallback wenn Desktop nicht verfügbar ist).
