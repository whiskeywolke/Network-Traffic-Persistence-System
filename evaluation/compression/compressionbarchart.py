import numpy as np
import matplotlib.pyplot as plt


labels = ['Raw\nPacket','Trimmed\nPayload','IP 5 Tuple','Compressed']

timestamps = np.array([16,16,16,8])
ipHeader = [20,20,5,0]
meanHeader = [17.96,17.96,3,0]
payloads = [314.45,0,0,0]
compressed = [0,0,0,9.2542]

width = 0.35
fig, ax = plt.subplots()


ax.bar(labels, timestamps, width, label='timestamp')
ax.bar(labels, ipHeader, width, label='ipheader', bottom=timestamps)
ax.bar(labels, meanHeader, width, label='mean header' , bottom=[x + y for x, y in zip(timestamps, ipHeader)])
ax.bar(labels, payloads, width, label='payload' , bottom=[x + y + z for x, y, z in zip(timestamps, ipHeader, meanHeader)])
ax.bar(labels, compressed, width, label='compressed' , bottom=[w + x + y + z for w, x, y, z in zip(timestamps, ipHeader, meanHeader, payloads)])
ax.legend()

ax.set_ylabel('Bytes')

ax.set_title('Compression Rate')

#ax.set_yscale("symlog")

plt.savefig('compression_rate_payload.png')


fig, ax = plt.subplots()

labels = ['Trimmed\nPayload','IP 5 Tuple','Compressed']

timestamps = [16,16,8]
ipHeader = [20,5,0]
meanHeader = [17.96,3,0]
payloads = [0,0,0]
compressed = [0,0,9.2542]

width = 0.35


ax.bar(labels, timestamps, width, label='timestamp')
ax.bar(labels, ipHeader, width, label='ipheader', bottom=timestamps)
ax.bar(labels, meanHeader, width, label='mean header' , bottom=[x + y for x, y in zip(timestamps, ipHeader)])
ax.bar(labels, payloads, width, label='payload' , bottom=[x + y + z for x, y, z in zip(timestamps, ipHeader, meanHeader)])
ax.bar(labels, compressed, width, label='compressed' , bottom=[w + x + y + z for w, x, y, z in zip(timestamps, ipHeader, meanHeader, payloads)])
ax.legend()

ax.set_ylabel('Bytes')

ax.set_title('Compression Rate')

plt.savefig('compression_rate.png')

