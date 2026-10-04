# Isolation Forest novelty

Isolation Forest is an unsupervised anomaly-detection algorithm. Instead of
learning labels for known rogue access points, it isolates observations through
random feature splits; behaviour requiring fewer splits to isolate is unusual.
SentinelShield trains it on historical normal Wi-Fi observations, enabling it to
identify signal, configuration, density, and reputation patterns not present in
the labelled attack set.

Random Forest and KNN are supervised classifiers: they estimate whether a scan
resembles previously labelled Fake or Legit examples. Isolation Forest supplies
an independent novelty signal, so a zero-day evil twin or rogue AP can be
flagged even when it does not resemble a known attack. This is valuable for
rogue-AP detection because adversaries can change an SSID, BSSID, channel,
encryption configuration, or transmit power while retaining abnormal joint
behaviour. The hybrid score combines supervised evidence, unsupervised novelty,
and deterministic security rules, improving defence-in-depth and providing a
research-paper distinction between signature-like classification and discovery
of unseen behaviour.
