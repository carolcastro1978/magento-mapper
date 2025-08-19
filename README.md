# MagentoMapper

A comprehensive GUI tool for analyzing and mapping Magento 2 components including events, plugins, and class preferences. Built with Python and tkinter for cross-platform compatibility.

## 🎯 Overview

MagentoMapper helps Magento 2 developers understand the complex relationships between different system components by scanning and visualizing:

- **Event Observers** - Events and their registered observers
- **Plugins** - Plugin classes and their target classes 
- **Preferences** - Class preferences and dependency injection overrides

## ✨ Features

### 🔍 Event Observer Mapper
- Scan all event observers across global, frontend, and adminhtml areas
- Advanced search functionality with multiple search types:
  - Partial matching
  - Exact matching  
  - Starts with matching
  - Fuzzy matching (handles typos)
  - Regex pattern matching
- Filter by vendor and area
- Real-time filtering without re-scanning
- Export results to JSON and CSV

### 🧩 Plugin Mapper
- Discover all Magento 2 plugins and their target classes
- Search by plugin class name or target class name
- Area-specific filtering (global/frontend/adminhtml)
- Vendor filtering capabilities
- Multiple search modes with fuzzy matching
- Export functionality with search metadata

### 🔧 Preference Mapper
- Map class preferences and dependency injection overrides
- Advanced filtering with multiple modes:
  - Contains, regex, starts with, ends with, exact match
  - Case-sensitive/insensitive options
- Live filtering as you type
- Area and vendor filtering
- Export preferences data

### 📊 Common Features
- **Intuitive GUI** - Easy-to-use graphical interface
- **Flexible Sorting** - Sort by name or count (ascending/descending)
- **Multi-format Export** - JSON and CSV export options
- **Performance Optimized** - Scan once, filter multiple times
- **Cross-platform** - Works on Windows, macOS, and Linux

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- tkinter (usually included with Python)

### Setup
1. Clone or download the repository
2. Navigate to the project directory
3. Install dependencies (if needed):
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
```bash
python main.py
```

### Building Executable (Optional)
To create a standalone executable:
```bash
pip install cx_Freeze
python setup.py build
```

## 📖 Usage

### Getting Started
1. Launch the application by running `python main.py`
2. Enter your Magento 2 root directory path
3. Select the analysis tool you want to use:
   - 🔍 **Event Observer Mapper**
   - 🔧 **Preference Class Mapper** 
   - 🧩 **Plugin Mapper**

### Event Observer Mapper
1. Configure area filters (global, frontend, adminhtml)
2. Set vendor filters (comma-separated, or "all")
3. Choose search type and enter event name filter
4. Click "Scan Magento Events"
5. Use live filtering to refine results
6. Export data as needed

### Plugin Mapper
1. Set vendor and area filters
2. Choose search type for plugin/target class filtering
3. Click "Scan Plugins"
4. Filter results in real-time
5. Export findings

### Preference Mapper
1. Configure vendor and area filters
2. Set up text filtering with various modes
3. Click "Scan Preferences"
4. Use live filtering for quick searches
5. Export preference mappings

## 🔧 Configuration

### Search Types
- **Partial Match**: Contains the search term (e.g., 'customer' finds 'customer_login')
- **Exact Match**: Exact match only
- **Starts With**: Name starts with the term (good for autocomplete)
- **Fuzzy Match**: Handles typos and similar names (60% similarity threshold)
- **Regex Pattern**: Use regular expressions for advanced patterns

### Area Filtering
- **Global**: Core Magento functionality
- **Frontend**: Customer-facing features
- **Adminhtml**: Admin panel functionality
- **Include ANY etc/* area**: Override area filters to include all areas

### Vendor Filtering
Filter results by vendor namespace (e.g., "Magento", "Custom", "Vendor_Module")

## 📁 Project Structure

```
MagentoMapper/
├── main.py                 # Main launcher application
├── event_mapper.py         # Event observer scanning logic
├── plugin_mapper.py        # Plugin mapping functionality  
├── preference_mapper.py    # Preference mapping tool
├── setup.py               # Build configuration for executable
├── main.spec              # PyInstaller spec file
└── README.md              # This file
```

## 🎨 Screenshots

### Main Launcher
The main interface allows you to select which analysis tool to use and specify your Magento 2 root directory.

### Event Observer Mapper
Advanced event scanning with multiple search types, area filtering, and real-time results.

### Plugin Mapper  
Comprehensive plugin analysis showing target classes and their interceptors.

### Preference Mapper
Class preference mapping with flexible filtering and export options.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is open source. Please refer to the license file for details.

## 🐛 Known Issues

- Large Magento installations may take longer to scan initially
- Complex regex patterns in search may impact performance

## 🔮 Future Enhancements

- [ ] Module dependency mapping
- [ ] Graphical relationship visualization
- [ ] Performance metrics and caching
- [ ] Command-line interface
- [ ] Database schema analysis
- [ ] Theme and layout mapping

## 📞 Support

For support, feature requests, or bug reports, please open an issue in the project repository.

## 🏷️ Version History

### v1.0
- Initial release with event, plugin, and preference mapping
- GUI interface with advanced filtering
- Export functionality
- Multi-platform support

---

**MagentoMapper** - Making Magento 2 component relationships visible and understandable.
