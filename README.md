# Director
Director is a Python-based network monitoring tool using Scapy and Matplotlib for real-time, ECG-style traffic visualization. It tracks DNS queries, HTTP traffic, and data usage, ideal for educational purposes and ethical network analysis. Perfect for admins and cybersecurity enthusiasts to understand network behaviors within authorized networks.

## Director: Real-Time Network Monitoring Tool

Director is an innovative, real-time network monitoring tool designed for network administrators, cybersecurity enthusiasts, and educational professionals seeking to gain insights into network traffic patterns and behaviors within their own networks. Leveraging the power of Python, Scapy for packet sniffing, and Matplotlib for dynamic data visualization, Director offers a comprehensive overview of network activities in an accessible, ECG-style graph. This tool is particularly useful for understanding data usage trends, identifying potential network anomalies, and enhancing cybersecurity education.

## Features

- **ECG-Style Data Visualization**: Utilizes Matplotlib to present network data usage in a dynamic, real-time graph that mimics the look of an ECG monitor, providing a modern and intuitive visualization of network traffic flow.
- **DNS Query Tracking**: Captures and logs DNS queries made by devices on the network, offering insights into the domains being accessed. This feature helps in understanding network behavior and detecting unusual patterns that could indicate cybersecurity threats.
- **HTTP Host Logging**: Identifies and logs hosts from unencrypted HTTP traffic, enabling users to see which websites are being accessed over the network. This capability is crucial for monitoring and auditing network usage policies.
- **Real-Time Monitoring**: Implements threading to perform packet sniffing and data analysis concurrently, ensuring that the tool can capture and display network traffic data without significant delays.
- **Ethical and Educational Focus**: Designed with an emphasis on ethical use and educational value, Director serves as a powerful tool for teaching and learning about network protocols, traffic analysis, and cybersecurity principles.

## Installation

Director requires Python 3 and the following Python packages: Scapy, Matplotlib. These can be installed using pip:

```sh
pip install scapy matplotlib
```

## Usage

To run Director, you must have administrative privileges due to the requirements for packet sniffing. On Linux and macOS, this can be achieved using `sudo`:

```sh
sudo python3 director.py
```

Upon execution, Director begins sniffing the network packets and visualizing the data usage in real-time. Additionally, it logs DNS queries and HTTP hosts accessed by devices on the network, displaying this information in the terminal for further analysis.

## Ethical Considerations

Director is intended for use only on networks where you have explicit permission to monitor traffic. It is essential to respect the privacy and legal restrictions of network monitoring and data capture. Director is designed for educational purposes, to aid in the understanding of network behaviors and to enhance cybersecurity practices.

## Contributing

Contributions to Director are welcome! Whether it's feature requests, bug reports, or code contributions, please feel free to make a pull request or open an issue on GitHub. We aim to foster an inclusive and welcoming community around Director.

## License

Director is released under the [MIT License](https://opensource.org/licenses/MIT). Please see the `LICENSE` file for more details.

## Acknowledgments

Director was created by leveraging the capabilities of several open-source projects, including Python, Scapy, and Matplotlib. We are grateful to the developers and contributors of these projects for their invaluable work.

---

Director is more than just a tool; it's a stepping stone towards understanding and securing our digital environments. We are excited to see how it will be used by educators, students, and professionals to enhance their knowledge and practices in network monitoring and cybersecurity.
