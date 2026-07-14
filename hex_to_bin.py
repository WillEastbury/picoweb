import sys, struct
words = [l.strip() for l in sys.stdin if l.strip()]
data = b''.join(struct.pack('<I', int(w, 16)) for w in words)
sys.stdout.buffer.write(data)
