# DoH Research

This repository contains the tools and data developed for our final project, focused on DNS-over-HTTPS (DoH) traffic analysis. The project aims to detect and characterize DoH traffic by capturing HTTPS traffic, extracting statistical and time-series features, and analyzing the traffic using various methods.

## Installation

To install the necessary dependencies, run the following command:

bash
pip install -r requirements.txt


## Usage

-**Running the Extractor**
To run the extractor module on a directory containing communication files (e.g., PCAP files), use the following command:
bash
Copy code
python dohlyzer.py -f "path/to/communication/files" -c "output_csv_file.csv"
This will process the input PCAP files and save the extracted data to the specified CSV file.

-**Running the Visualizer**
To run the visualizer and visualize the clumps from the extracted data, use the following command:
bash
python main.py

-**Analyzer Usage**
In the analyzer folder, a Jupyter notebook (.ipynb) file is provided, which demonstrates how to load and use the trained models for DoH traffic classification. You can use it to apply the models to the extracted traffic features.
## Dependencies

Refer to requirements.txt for the full list of required Python packages.

## Extractor Module

The extractor module is responsible for the core functions of traffic analysis, which include:

- **Capturing HTTPS packets**: Captures packets directly from network interfaces or reads input PCAP files containing captured traffic.
- **Flow grouping**: Groups packets into flows based on their source and destination IP addresses and ports, enabling analysis of traffic at the flow level rather than individual packets.
- **Feature extraction**: Extracts a variety of features necessary for traffic analysis, including both statistical and time-series features. These features are crucial for identifying and characterizing DoH traffic in comparison to other types of traffic.

## Analyzer Module

The analyzer module is designed to assist in the development and evaluation of machine learning models for traffic analysis:

- **Deep Neural Network (DNN) models**: The module can be used to create and train the proposed DNN models for classifying and characterizing DoH traffic.
- **Benchmarking**: It allows for benchmarking the DNN models against aggregated traffic data. This data is provided in the form of clumps, which are created by the **extractor** module. The clumps file aggregates and organizes features to enable effective traffic classification.

## Visualizer Module

The visualizer module is used to interpret and visualize the clumps files created by the **Extractor** module. This visualization helps provide insights into the structure and behavior of the traffic, assisting in feature analysis and model evaluation. It offers visual representations of key data points to better understand the traffic flow and feature distribution.

## Dataset

We created an adapted dataset consisting of network traffic of 3 types:
- **Non-DoH Traffic**
- **Benign-DoH Traffic**
- **Malicious-DoH Traffic**

For the purpose of capturing the traffic, we used **Wireshark**. The captured files were organized in a structured manner, constituting our dataset. This dataset can be used to analyze the behavior of different types of traffic, especially to identify and distinguish DoH traffic from other forms of HTTPS traffic.

