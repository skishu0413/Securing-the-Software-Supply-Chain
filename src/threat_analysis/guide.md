# Threat Analysis System

This directory contains all components for the adaptive threat analysis system that enhances dependency security scanning.

## Components

### Command Line Interface
- **`cli.py`** - Management interface for the threat analysis system
  - View threat intelligence statistics and discovered attack patterns
  - Tune similarity thresholds for different deployment environments
  - Report false positives and confirmed security threats
  - Export and manage threat intelligence data

### Threat Intelligence Trainer
- **`trainer.py`** - Threat intelligence training system for pattern analysis
  - Pre-train with popular packages from PyPI, npm, Maven Central
  - Process large datasets efficiently with concurrent threat analysis
  - Bootstrap threat intelligence for production environments

### Core Threat Processing Engine
- **`threat_processor.py`** - Enterprise threat processing engine
  - Real-time attack pattern recognition and analysis
  - Dynamic threshold optimization based on threat landscape
  - Automatic discovery of new attack vectors and techniques
  - Continuous threat intelligence processing and feedback integration

### Module Info
- **`__init__.py`** - Python module initialization

## Quick Start

```bash
# From the project root directory:

# View threat analysis system status
python3 src/threat_analysis/cli.py stats

# Train the system with threat intelligence
python3 src/threat_analysis/trainer.py --ecosystems all --limit 500

# Optimize detection thresholds for your environment  
python3 src/threat_analysis/cli.py tune pypi --existing 85 --missing 80
```

## Overview

The Threat Analysis System automatically discovers threat patterns, learns from real-world attack data, and optimizes detection thresholds to improve accuracy over time. This eliminates the need for manual updates when new attack patterns emerge or when scanning large datasets.

## Key Features

### 🔍 **Automatic Threat Discovery**
- **Attack Pattern Recognition**: Learns which attack patterns are common in each ecosystem
- **Threshold Optimization**: Adjusts similarity thresholds based on false positive rates
- **Signature Recognition**: Discovers naming patterns and character substitutions used in attacks
- **Ecosystem Intelligence**: Understands ecosystem-specific threat characteristics

### 📊 **Real-time Threat Adaptation**
- **Dynamic Threat Patterns**: Automatically updates common attack targets list
- **Learned Thresholds**: Uses ecosystem-specific thresholds instead of hardcoded values
- **Continuous Improvement**: Gets better with more threat data
- **Feedback Integration**: Learns from false positive and confirmed threat reports

### ⚡ **Performance Optimization**
- **Caching System**: Stores learned data locally for fast access
- **Batch Processing**: Efficiently processes large datasets
- **Async Operations**: Concurrent package metadata fetching
- **Progressive Learning**: Updates incrementally without blocking

## Architecture

```
┌─────────────────────────┐
│   Detection Engine      │
│  ┌─────────────────────┐│
│  │ Static Config       ││  ← Fallback values
│  └─────────────────────┘│
│  ┌─────────────────────┐│
│  │ Threat Analysis     ││  ← Dynamic threat intelligence
│  │ - Attack patterns   ││
│  │ - Thresholds        ││
│  │ - Signatures        ││
│  └─────────────────────┘│
└─────────────────────────┘
           │
           ▼
┌─────────────────────────┐
│  Threat Intelligence    │
│ ┌─────────────────────┐ │
│ │ learning_data.json  │ │ ← Package metadata & threat stats
│ └─────────────────────┘ │
│ ┌─────────────────────┐ │
│ │ popular_packages.json│ │ ← Discovered attack targets
│ └─────────────────────┘ │
│ ┌─────────────────────┐ │
│ │ learned_patterns.json│ │ ← Thresholds & attack patterns
│ └─────────────────────┘ │
└─────────────────────────┘
```

## Usage

### Basic Integration

The threat analysis system is automatically integrated into the detection engine. Just use the scanner normally:

```bash
python3 -m src.main requirements.txt --type pypi
```

The system will:
1. Learn from legitimate packages it encounters
2. Update threat pattern databases dynamically
3. Adjust thresholds based on ecosystem patterns
4. Save threat intelligence for future scans

### Threat Intelligence Training

For large-scale deployments, pre-train the system:

```bash
# Train from threat intelligence in all ecosystems
python3 src/threat_analysis/trainer.py --ecosystems all --limit 1000

# Train from specific ecosystem
python3 src/threat_analysis/trainer.py --ecosystems pypi --limit 500

# Use custom threat intelligence
python3 src/threat_analysis/trainer.py --custom-packages my_packages.json
```

### Threat Analysis Management

Monitor and manage the threat analysis system:

```bash
# Show threat analysis statistics
python3 src/threat_analysis/cli.py stats

# View discovered attack patterns
python3 src/threat_analysis/cli.py popular --ecosystem pypi --limit 20

# Check current thresholds
python3 src/threat_analysis/cli.py thresholds

# Report false positive for analysis
python3 src/threat_analysis/cli.py report-fp badpackage goodpackage pypi

# Export threat intelligence
python3 src/threat_analysis/cli.py export threat_intel.json

# Reset threat data (if needed)
python3 src/threat_analysis/cli.py reset --force
```

## Learning Data

### Package Metadata Learning

The system learns from package metadata:

```python
{
  "package_popularity": {
    "pypi:requests": {
      "popularity": 115.5,
      "last_seen": 1699123456,
      "metadata_quality": 0.9
    }
  },
  "ecosystem_stats": {
    "pypi": {
      "total_packages": 1250,
      "avg_popularity": 45.2
    }
  }
}
```

### Dynamic Popular Packages

Automatically discovered packages:

```python
{
  "pypi": ["requests", "numpy", "pandas", "django", "flask", ...],
  "npm": ["lodash", "react", "express", "axios", ...],
  "maven": ["org.springframework:spring-core", ...]
}
```

### Learned Thresholds

Ecosystem-specific thresholds:

```python
{
  "similarity_thresholds": {
    "pypi": {"existing": 82, "missing": 77},
    "npm": {"existing": 78, "missing": 73},
    "maven": {"existing": 85, "missing": 80}
  }
}
```

## Configuration

### Learning Parameters

Key parameters in `learning_system.py`:

```python
class PackageLearningSystem:
    def __init__(self):
        # Learning sensitivity
        self.min_popularity_samples = 10
        self.pattern_confidence_threshold = 0.7
        
        # Update frequency
        self.popularity_update_interval = 24 * 3600  # 24 hours
```

### Tuning for Different Environments

#### High-Security Environment
```bash
# Stricter thresholds
python3 learning/learning_tool.py tune pypi --existing 85 --missing 80
python3 learning/learning_tool.py tune npm --existing 85 --missing 80
```

#### Development/Research Environment
```bash
# More lenient thresholds
python3 learning/learning_tool.py tune pypi --existing 75 --missing 70
python3 learning/learning_tool.py tune npm --existing 75 --missing 70
```

## Advanced Features

### Feedback Learning

The system learns from user feedback:

```python
# Report false positive
learning_system.report_false_positive('package', 'claimed_target', 'pypi')

# Report confirmed typosquat
learning_system.report_confirmed_typosquat('malicious', 'legitimate', 'pypi')
```

### Custom Package Lists

Train on organization-specific packages:

```json
{
  "pypi": ["myorg-utils", "myorg-core", "myorg-auth"],
  "npm": ["@myorg/common", "@myorg/ui"],
  "maven": ["com.myorg:core", "com.myorg:utils"]
}
```

### API Integration

Integrate with CI/CD pipelines:

```python
from suspicious_package_detector.learning_system import get_learning_system

learning_system = get_learning_system()

# Get current stats
stats = learning_system.get_learning_stats()

# Check if updates needed
if learning_system.should_update_popularity_data():
    # Trigger batch learning
    pass
```

## Performance Considerations

### Memory Usage
- Learning data: ~10-50MB for 10,000 packages
- Cache files: Updated incrementally
- Memory footprint: <100MB during operation

### Network Usage
- Initial learning: 1-2 API calls per package
- Ongoing operation: Only for unknown packages
- Batch learning: Concurrent requests (configurable)

### Storage
- Cache directory: `cache/` (configurable)
- Files automatically managed
- Periodic cleanup of old data

## Monitoring

### Key Metrics

```bash
python3 learning_tool.py stats
```

Output:
```
=== Learning System Statistics ===
Total packages learned from: 2,450
Last updated: 2025-11-01 16:30:00

Popular packages discovered:
  pypi: 125 packages
  npm: 87 packages
  maven: 43 packages

Ecosystem popularity averages:
  pypi: 52.3
  npm: 41.7
  maven: 38.9

False positives reported: 3
Confirmed typosquats: 12
```

### Health Checks

- **Learning rate**: Should increase with dataset size
- **False positive rate**: Should be <5-10%
- **Threshold adaptation**: Should stabilize over time
- **Popular package discovery**: Should grow logarithmically

## Troubleshooting

### Common Issues

1. **No packages learned**
   ```bash
   # Check network connectivity
   curl https://pypi.org/pypi/requests/json
   
   # Run batch training
   python3 src/threat_analysis/trainer.py --ecosystems pypi --limit 10
   ```

2. **High false positive rate**
   ```bash
   # Increase thresholds
   python3 src/threat_analysis/cli.py tune pypi --existing 85 --missing 80
   
   # Report false positives
   python3 src/threat_analysis/cli.py report-fp package target ecosystem
   ```

3. **Training data corruption**
   ```bash
   # Reset training data
   python3 src/threat_analysis/cli.py reset --force
   
   # Rebuild with batch training
   python3 src/threat_analysis/trainer.py --ecosystems all --limit 500
   ```

### Debug Mode

Enable verbose logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from suspicious_package_detector.learning_system import get_learning_system
learning_system = get_learning_system()
```

## Migration Guide

### From Static Configuration

1. **Backup current config**:
   ```bash
   cp src/suspicious_package_detector/config.py config_backup.py
   ```

2. **Run initial training**:
   ```bash
   python3 src/threat_analysis/trainer.py --ecosystems all --limit 500
   ```

3. **Verify thresholds**:
   ```bash
   python3 src/threat_analysis/cli.py thresholds
   ```

4. **Test detection**:
   ```bash
   python3 -m src.main test_requirements.txt --type pypi
   ```

### Gradual Migration

Start with learning enabled but keep static fallbacks:
- Learning system provides dynamic data
- Static config used when learning data unavailable
- Gradually increase reliance on learned data

## Best Practices

### 🚀 **Deployment**
1. Pre-train with batch training before production
2. Monitor false positive rates initially
3. Set up periodic batch training (weekly/monthly)
4. Back up training data regularly

### 🔧 **Tuning**
1. Start with default thresholds
2. Adjust based on your security requirements
3. Use feedback to improve accuracy
4. Monitor ecosystem-specific patterns

### 📈 **Scaling**
1. Use concurrent batch training for large datasets
2. Implement distributed training for multiple environments
3. Share training data across similar environments
4. Use custom package lists for organization-specific packages

## Future Enhancements

- **Machine Learning**: Integration with ML models for advanced pattern recognition
- **Collaborative Learning**: Share anonymized learning data across installations
- **Real-time Updates**: Live package popularity tracking
- **Advanced Analytics**: Threat intelligence integration
- **Performance Optimization**: Improved caching and prediction algorithms

---

The Machine Learning System transforms the static detection engine into an adaptive, intelligent system that improves with every scan. It's designed to handle real-world scale while maintaining high accuracy and low false positive rates.

This unified guide provides complete documentation for all ML system components in one convenient location.