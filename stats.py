import matplotlib.pyplot as plt

def update_protocol_chart(tcp_count, udp_count, other_count):
    labels = ['TCP', 'UDP', 'Other']
    sizes = [tcp_count, udp_count, other_count]
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.draw()
