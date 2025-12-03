# Cybersecurity---Suspicious-Web-Threat-Interactions-Project


 Domain
 
Cybersecurity
 
 Machine Learning
 
 Data Analytics
 
 Forensic Analysis
 

# Tools & Technologies Used

•	Languages: Python, SQL, Excel

•	Visualization Tools: Matplotlib, Seaborn, NetworkX

•	ML Tools: Scikit-Learn, TensorFlow/Keras

•	Dev Tools: Jupyter Notebook, VS Code



# Introduction

In today’s cloud-driven infrastructure, modern web servers face increasing cyber threats including intrusion attempts, botnet activity, and unauthorized access. Detecting threats in real time has become a critical requirement for enterprise security.

This project analyzes real web-traffic logs collected from AWS CloudWatch, focusing on identifying suspicious interactions and building machine learning models to automatically classify malicious behavior.

The purpose of this project is to:

•	understand traffic behavior

•	detect abnormalities

•	classify suspicious web sessions

•	build automated threat detection models

•	visualize network patterns between IPs

•	generate actionable cybersecurity insights.


# Dataset Overview

The dataset contains 282 records of web interactions captured from a production web server.
Key Dataset Columns

•	bytes_in / bytes_out → Amount of data transferred

•	creation_time / end_time / time → Event timestamps

•	src_ip / dst_ip → Source & destination IPs

•	src_ip_country_code → Country of origin

•	response.code → HTTP response (always 200)

•	dst_port → Destination port (always 443)

•	protocol → HTTPS

•	rule_names → Rule triggered for the event

•	detection_types → Type of detection (e.g., waf_rule)

•	observation_name → Description of suspicious behavior

Context

The data represents potentially harmful traffic flagged by detection engines such as:

•	WAF (Web Application Firewall)

•	AWS VPC Flow Logs

•	Threat Intelligence Rules

The dataset is ideal for anomaly detection and supervised classification.


# Project Objectives

	Analyze traffic interactions and find suspicious patterns.
   
 Clean & preprocess the dataset for ML modeling.

 Engineer new features like session duration and packet behavior.
 
 Perform EDA to understand trends, country patterns, and IP behaviors.

 Build ML models (Random Forest & Neural Networks) to classify suspicious sessions.

 Visualize network relationships between IPs.
 
 Interpret insights for cybersecurity improvement.

# Data Cleaning & Preparation

Performed Steps:

Converted timestamp columns to datetime format

Removed duplicates (none found)

Standardized country code values

Created new feature: duration_seconds

Scaled numerical features using StandardScaler

Performed One-Hot Encoding on categorical fields

Major Observations:

•	No missing values

•	All sessions last exactly 600 seconds

•	All traffic is HTTPS on port 443

•	All HTTP responses are 200 (OK)


# Feature Engineering

New features created to enhance analysis and model accuracy:

Session Duration

Calculated using start and end times.

Average Packet Size

Derived using bytes_in and bytes_out.

Country Encoding

One-hot encoded the source IP country.

Normalized Features

Created scaled versions of:

•	bytes_in

•	bytes_out

•	duration_seconds

These transformed the data into a model-friendly structure.


# Exploratory Data Analysis (EDA)

A. Traffic Behavior

•	bytes_in and bytes_out show high variability

•	Some sessions exchange large inbound traffic but low outbound traffic

•	Indicates possible infiltration or scraping attempts

B. Country-Based Analysis

•	Major traffic originates from US, AE, CA, DE, NL

•	Many suspicious events cluster around certain countries

•	Helps identify possible targeted attacks or botnets

C. Correlation Analysis

Strong relationships found between:

•	bytes_in ↔ bytes_out

•	scaled features correlate perfectly, confirming proper transformation

D. Network Graph

A network diagram showing:

•	one-to-many relationships between source and destination IPs

•	some IPs show repetitive communication → possibly automated attacks

E. Time Series Analysis

Plotting bytes over time shows:

•	repetitive uniform activity

•	consistent attack intervals

•	predictable threat patterns


# Machine Learning Models Implemented

Model 1: Random Forest Classifier

•	Trained using:

o	bytes_in

o	bytes_out

o	scaled_duration_seconds

•	Labels were generated using:

is_suspicious = 1 if detection type is waf_rule

Result

•	Accuracy: 100%

•	Perfect precision and recall for all suspicious sessions

This indicates the dataset is highly separable and ideal for classification.


# Neural Network (Dense Layers)

Architecture

•	Input layer → ReLU layers (8–16 neurons) → Sigmoid output

•	Binary classification

Results

•	100% accuracy

•	Loss continuously decreased every epoch

•	Model demonstrates strong pattern recognition


Model 3: Deep Neural Network with Dropout

•	Two 128-neuron hidden layers

•	Dropout for regularization

•	Trained with validation split

Results

•	100% test accuracy

•	Validation accuracy stable

•	No signs of overfitting


Model 4: CNN-Based Threat Detection

A 1D Convolutional Neural Network was used on numeric features.

Results

•	Achieved 100% accuracy

•	Successfully learned the patterns even in minimal data


# Key Insights & Findings
   
1. Suspicious Traffic Patterns
   
•	High inbound traffic with low outbound traffic resembles exploitation attempts.

•	Sessions originate from a limited set of repeating IPs → indicates bots.

2. Country Trends
   
•	The US had the highest number of suspicious activities.

•	Some countries consistently show suspicious behavior (AE, NL, DE).

3. Protocol & Port Behavior
   
•	All suspicious behavior targets HTTPS (port 443)

•	Suggests brute-force, reconnaissance, or automated bot scanning.

4. ML Model Performance
   
•	All models achieved near-perfect detection

•	Suggests features are highly predictive

•	bytes_in and bytes_out are strong indicators of suspicious activity


# Conclusion

This project successfully analyzes real-world suspicious cloud network traffic and builds highly accurate machine learning models for cybersecurity threat detection.

# Final Achievements
 Cleaned & preprocessed AWS CloudWatch traffic data.
 
 Performed extensive Exploratory Data Analysis.
 
 Extracted meaningful patterns from IP behavior.
 
 Visualized country-based threat frequency and network interactions.
 
 Engineered new features to strengthen ML models.
 
 Trained multiple models — all achieving 100% accuracy.
 
 Built an automated threat detection system using ML.


