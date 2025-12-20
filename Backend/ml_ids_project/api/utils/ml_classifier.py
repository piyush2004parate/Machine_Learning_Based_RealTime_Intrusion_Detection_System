import os
import math
from collections import deque, defaultdict
from typing import Deque, Dict, List, Tuple

# Optional torch import; if unavailable, we fall back to heuristics
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False


def _proto_to_id(proto: str) -> int:
    p = (proto or "").upper()
    if p == "TCP":
        return 1
    if p == "UDP":
        return 2
    if p == "ICMP":
        return 3
    if p == "DNS":
        return 4
    return 0  # IP/other


def _safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return float(default)


if TORCH_AVAILABLE:
    class _CNNLSTMNet(nn.Module):
        """Lightweight CNN+LSTM for sequence classification.

        Input shape: (B, T, F) where F is feature size.
        We transpose to (B, F, T) for Conv1d, then feed to LSTM.
        Output: logits over 3 classes [Normal, Anomaly, Malware].
        """

        def __init__(self, feature_dim: int, hidden_dim: int = 64, num_classes: int = 3):
            super().__init__()
            conv_channels = 32
            self.conv1 = nn.Conv1d(feature_dim, conv_channels, kernel_size=3, padding=1)
            self.bn1 = nn.BatchNorm1d(conv_channels)
            self.conv2 = nn.Conv1d(conv_channels, conv_channels, kernel_size=3, padding=1)
            self.bn2 = nn.BatchNorm1d(conv_channels)
            self.lstm = nn.LSTM(input_size=conv_channels, hidden_size=hidden_dim, num_layers=1, batch_first=True, bidirectional=True)
            self.fc = nn.Linear(hidden_dim * 2, num_classes)

        def forward(self, x):  # x: (B, T, F)
            x = x.transpose(1, 2)  # (B, F, T)
            x = F.relu(self.bn1(self.conv1(x)))
            x = F.relu(self.bn2(self.conv2(x)))
            x = x.transpose(1, 2)  # (B, T, C)
            out, _ = self.lstm(x)  # (B, T, 2H)
            # take last timestep
            out = out[:, -1, :]
            logits = self.fc(out)
            return logits
else:
    _CNNLSTMNet = None


class AnomalyDetector:
    """Stateful live detector with optional CNN-LSTM backend.

    Public API:
    - classify_packet(features: dict) -> (status, severity)

    Features expected (best effort):
    - 'protocol': str
    - 'length': int
    - 'timestamp': float (seconds)
    - optionally 'src_ip', 'dst_ip' for per-flow windowing
    """

    def __init__(self,
                 window_size: int = 20,
                 min_infer_size: int = 10,
                 model_path_env: str = "IDS_MODEL_PATH",
                 default_model_path: str = "model/cnn_lstm_ids.pt"):
        self.window_size = int(window_size)
        self.min_infer_size = int(min_infer_size)

        # Per-flow buffers: key -> deque of feature vectors
        self.buffers: Dict[str, Deque[List[float]]] = defaultdict(lambda: deque(maxlen=self.window_size))
        # Track last timestamp per flow for inter-arrival deltas
        self.last_ts: Dict[str, float] = {}

        self.feature_dim = 5  # [len_norm, proto_id, dt_norm, hour_sin, hour_cos]

        self.model = None
        self.device = "cpu"
        if TORCH_AVAILABLE:
            try:
                model_path = os.getenv(model_path_env, default_model_path)
                self.model = _CNNLSTMNet(self.feature_dim)
                if os.path.isfile(model_path):
                    state = torch.load(model_path, map_location="cpu")
                    # Support both bare state_dict and checkpoint dict
                    state_dict = state.get("model_state_dict", state) if isinstance(state, dict) else state
                    self.model.load_state_dict(state_dict)
                self.model.eval()
            except Exception as e:
                # If loading fails, we will fall back to heuristics
                self.model = None

    # --------------- Feature engineering ---------------
    def _flow_key(self, features: dict) -> str:
        src = str(features.get("src_ip", ""))
        dst = str(features.get("dst_ip", ""))
        proto = str(features.get("protocol", "")).upper()
        return f"{src}>{dst}:{proto}"

    @staticmethod
    def _norm_len(length: float) -> float:
        # Cap at typical MTU-ish 1500 for scaling
        return max(0.0, min(float(length), 2000.0)) / 1500.0

    @staticmethod
    def _norm_dt(dt: float) -> float:
        # Clip to 2 seconds, scale to [0,1]
        dt = max(0.0, min(float(dt), 2.0))
        return dt / 2.0

    @staticmethod
    def _time_enc(ts: float) -> Tuple[float, float]:
        try:
            # map wall-clock second-of-day to sin/cos
            sod = int(ts % 86400)
            ang = 2.0 * math.pi * (sod / 86400.0)
            return math.sin(ang), math.cos(ang)
        except Exception:
            return 0.0, 1.0

    def _vectorize(self, features: dict) -> Tuple[str, List[float]]:
        key = self._flow_key(features)
        ts = _safe_float(features.get("timestamp"), 0.0)
        length = _safe_float(features.get("length"), 0.0)
        proto_id = float(_proto_to_id(features.get("protocol")))

        prev_ts = self.last_ts.get(key, None)
        dt = (ts - prev_ts) if prev_ts is not None else 0.0
        self.last_ts[key] = ts

        len_norm = self._norm_len(length)
        dt_norm = self._norm_dt(dt)
        s, c = self._time_enc(ts)

        vec = [len_norm, proto_id, dt_norm, s, c]
        return key, vec

    # --------------- Heuristic fallback ---------------
    @staticmethod
    def _heuristic_status_severity(features: dict) -> Tuple[str, str]:
        try:
            protocol = str(features.get("protocol", "")).upper()
            length = int(features.get("length", 0))
            if length > 1500:
                return ("Anomalous", "High")
            if protocol in ("DNS", "ICMP") and length > 600:
                return ("Anomalous", "Medium")
            if protocol == "UDP" and length > 900:
                return ("Anomalous", "Medium")
            return ("Normal", "Low")
        except Exception:
            return ("Normal", "Low")

    # --------------- Public API ---------------
    def classify_packet(self, features: dict) -> Tuple[str, str]:
        """Classify a packet into status and severity.

        Returns (status, severity) where:
        - status: 'Normal' | 'Anomalous' | 'Blocked'
        - severity: 'Low' | 'Medium' | 'High' | 'Critical'
        """
        # Force heuristic-only classification (CNN-LSTM disabled)
        return self._heuristic_status_severity(features)
