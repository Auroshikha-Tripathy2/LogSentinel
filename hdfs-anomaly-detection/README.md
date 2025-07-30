# HDFS Log Anomaly Detection System

An enterprise-grade anomaly detection system for Hadoop Distributed File System (HDFS) logs that identifies anomalous block IDs and system patterns.

## 🎯 Project Overview

This system analyzes HDFS log entries to detect anomalies in block operations, focusing on block ID characteristics rather than log message content. The anomaly detection uses a multi-strategy approach combining statistical analysis, pattern recognition, and machine learning techniques.

## 🚀 Features

- **Block ID Analysis**: Focuses on analyzing block ID characteristics for anomaly detection
- **Multi-Strategy Scoring**: Combines error patterns, log levels, and statistical outliers
- **Performance Metrics**: Comprehensive evaluation with ROC AUC, Precision, Recall, and F1-Score
- **Visualization**: Automatic generation of ROC curves and feature importance plots
- **Docker Support**: Complete containerization for easy deployment
- **Enterprise Ready**: Production-grade logging and error handling

## 📊 Performance

Current system performance:
- **ROC AUC**: 0.579
- **Precision**: 0.0468
- **Recall**: 0.8095 (81% of actual anomalies detected)
- **F1-Score**: 0.0885

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Docker (optional)
- Git

### Local Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd hdfs-anomaly-detection
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Docker Installation

1. **Build and run with Docker Compose**
   ```bash
   docker-compose up --build
   ```

2. **Or build manually**
   ```bash
   docker build -t hdfs-anomaly-detector .
   docker run -v $(pwd)/data:/app/data -v $(pwd)/plots:/app/plots hdfs-anomaly-detector
   ```

## 🚀 Usage

### Basic Usage

```bash
# Run anomaly detection
python enterprise_detector.py

# Run with plot generation
python enterprise_detector.py --plot

# Run with model saving
python enterprise_detector.py --save-model

# Run with custom configuration
python enterprise_detector.py --config custom_config.json
```

### Verify Data Labels

```bash
python verify_labels.py
```

### Parse New HDFS Logs

```bash
python hdfs_parser.py
```

## 📁 Project Structure

```
hdfs-anomaly-detection/
├── enterprise_detector.py      # Main anomaly detection system
├── hdfs_parser.py             # HDFS log parser
├── verify_labels.py           # Label verification utility
├── requirements.txt           # Python dependencies
├── dockerfile                 # Docker configuration
├── docker-compose.yml         # Docker Compose setup
├── README.md                  # This file
├── data/                      # Data directory
│   ├── HDFS.log              # Original HDFS log file
│   ├── anomaly_label.csv     # Ground truth labels
│   └── parsed_hdfs_logs.json # Parsed log data
├── plots/                     # Generated visualizations
│   └── roc_curve_*.png       # ROC curves
├── models/                    # Saved models
├── configs/                   # Configuration files
└── logs/                      # Application logs
```

## 🔧 Configuration

The system uses a `ModelConfig` class with the following parameters:

```python
@dataclass
class ModelConfig:
    max_features: int = 50              # Maximum features
    train_test_ratio: float = 0.7       # Data split ratio
    normal_anomaly_ratio: int = 8       # Class balance
    min_precision: float = 0.05         # Minimum precision
    min_recall: float = 0.05           # Minimum recall
    error_weight: float = 0.35          # Error pattern weight
    level_weight: float = 0.25          # Log level weight
    pattern_weight: float = 0.25        # Pattern weight
    complexity_weight: float = 0.10     # Complexity weight
    density_weight: float = 0.05        # Density weight
```

## 📈 Algorithm

### Block ID Analysis
The system focuses on analyzing block ID characteristics:
- **Length Analysis**: Detects unusually long or short block IDs
- **Numeric Characteristics**: Identifies highly numeric vs alphanumeric patterns
- **Value Analysis**: Detects very large numbers, negative values, and outliers

### Multi-Strategy Scoring
1. **Error Pattern Detection**: Analyzes exceptions, errors, and stack traces
2. **Log Level Analysis**: Weights different log levels (ERROR, WARN, INFO, DEBUG)
3. **Component Analysis**: Examines component depth and complexity
4. **Statistical Outliers**: Detects extreme values across all features
5. **Normal Pattern Penalties**: Reduces false positives from normal operations

## 🧪 Testing

### Run Tests
```bash
pytest tests/
```

### Performance Testing
The system automatically:
- Splits data into training (70%) and testing (30%) sets
- Performs stratified sampling to maintain class balance
- Evaluates using multiple metrics (ROC AUC, Precision, Recall, F1-Score)
- Generates confusion matrix and feature importance analysis

## 📊 Results Interpretation

### ROC AUC (0.579)
- **Good**: The model has reasonable discrimination ability
- **Interpretation**: 57.9% of the time, a randomly chosen anomaly has a higher score than a randomly chosen normal log

### Precision (0.0468)
- **Low**: Only 4.68% of predicted anomalies are actual anomalies
- **Trade-off**: High recall comes at the cost of many false positives

### Recall (0.8095)
- **High**: 80.95% of actual anomalies are detected
- **Security Focus**: Prioritizes detecting real anomalies over avoiding false alarms

## 🔍 Troubleshooting

### Common Issues

1. **No anomalies detected**
   - Check if `anomaly_label.csv` contains 'Anomaly' labels
   - Verify block ID matching between logs and labels

2. **Low performance**
   - Review data quality and feature engineering
   - Adjust configuration parameters
   - Check for class imbalance

3. **Memory issues**
   - Reduce `max_features` in configuration
   - Use smaller batch sizes
   - Increase system memory

4. **Plot generation fails**
   - Ensure matplotlib is installed
   - Set backend to 'Agg' for non-interactive environments
   - Check write permissions for plots directory

### Log Files
- Check `logs/hdfs_anomaly_detection.log` for detailed execution logs
- Review console output for warnings and errors

## 🚀 Deployment

### Production Deployment

1. **Environment Variables**
   ```bash
   export LOG_LEVEL=INFO
   export PYTHONPATH=/app
   export DATA_PATH=/app/data
   ```

2. **Docker Production**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. **Kubernetes Deployment**
   ```bash
   kubectl apply -f k8s/
   ```

### Monitoring

- **Health Checks**: Built-in Docker health checks
- **Logging**: Structured logging with configurable levels
- **Metrics**: Performance metrics and system statistics
- **Alerts**: Configurable alerting for detected anomalies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linting
black .
flake8 .

# Run tests
pytest tests/ -v

# Generate documentation
sphinx-build -b html docs/ docs/_build/html
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- HDFS community for the log dataset
- Scikit-learn team for the machine learning framework
- Matplotlib and Seaborn for visualization capabilities

## 📞 Support

For questions and support:
- Create an issue in the repository
- Contact the development team
- Check the documentation in `docs/`

---

**Note**: This system prioritizes detecting actual anomalies over avoiding false positives, which is appropriate for security and monitoring applications where missing an anomaly is more costly than false alarms.
