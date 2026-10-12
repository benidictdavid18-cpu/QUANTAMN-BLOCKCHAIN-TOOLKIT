"""
NEGATIVE CASE: identifiers that superficially resemble crypto primitives.
A naive substring scanner flags these; none is a cryptographic call site.
Expected findings: 0
"""


class LayoutEngine:
    def __init__(self):
        self.width = 1024
        self.bandwidth = 10_000
        self.sha256_cache_enabled = False
        self.rsa_config_path = "/etc/app/rsa_config.toml"
        self.dh_group_label = "display-height"

    def compute_width(self, padding):
        return self.width + padding

    def bandwidth_per_channel(self, channels):
        return self.bandwidth / max(1, channels)

    def describe(self):
        return f"{self.width}x{self.bandwidth}"


class CacheKeyBuilder:
    """Builds cache keys. Uses no cryptography at all."""

    def __init__(self):
        self.ecdsa_feature_flag = False
        self.aes_region_code = "AES"

    def build(self, namespace, identifier):
        return f"{namespace}:{identifier}"

    def region(self):
        return self.aes_region_code
