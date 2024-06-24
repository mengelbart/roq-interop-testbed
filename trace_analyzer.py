
import pyshark


class TraceAnalyzer:
    _filename = ""

    
    def __init__(self, filename, keylog_file):
        self._filename = filename
        self._keylog_file = keylog_file

    
    def get_packets(self):
        override_prefs = {}
        override_prefs["tls.keylog_file"] = self._keylog_file
        cap = pyshark.FileCapture(
            self._filename,
            override_prefs=override_prefs,
            decode_as={"udp.port==8080": "quic"},
        )
        packets = []
        try:
            for p in cap:
                packets.append(p)
            cap.close()
        except Exception as e:
            print(e)
        
        for p in packets:
            try:
                if hasattr(p["quic"], "decryption_failed"):
                    print("at least one packet could not be decrypted")
                    print(p)
            except Exception as e:
                print(e)

        return packets