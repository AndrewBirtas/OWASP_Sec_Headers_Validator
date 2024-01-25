# OWASP Security Headers Validator
# HeaderHawk

A simple script that verifies a server's headers against the recommended security headers from OWASP Secure Headers Project

## Table of Contents
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Contributing](#contributing)

## Getting Started

Explain how to get a copy of your project up and running on a local machine.

### Prerequisites

List of dependencies that need to be installed:
  -Ruby 2.7.2
  -Nokogiri gem
  -Colorize gem

### Installation

1. Clone the repository: git clone https://github.com/AndrewBirtas/OWASP_Sec_Headers_Validator.git
2. Navigate to the project directory: cd OWASP_Sec_Headers_Validator
3. Install dependencies: bundle install

## Usage

The script can take a link or a Burp Request file in order to validate if the Headers match to recommended headers from OWASP Secure Header Project.

![Screenshot_2024-01-25_05-41-11](https://github.com/AndrewBirtas/OWASP_Sec_Headers_Validator/assets/71767826/48ee5542-9a58-41e1-a77a-980b77f6d558)

![Screenshot_2024-01-25_05-42-44](https://github.com/AndrewBirtas/OWASP_Sec_Headers_Validator/assets/71767826/408a0c4b-7db2-474c-80bd-fa22435f275a)

![Screenshot_2024-01-25_05-45-47](https://github.com/AndrewBirtas/OWASP_Sec_Headers_Validator/assets/71767826/fa31d38f-1095-45e3-ac36-84af1aaa4199)

![Screenshot_2024-01-25_05-46-04](https://github.com/AndrewBirtas/OWASP_Sec_Headers_Validator/assets/71767826/1a312b4e-97bc-4a26-b6d8-c6d269d613dc)


## Options
    -u, --url URL            Specify the URL.
    -c, --cookie NAME=VALUE  Specify a header.
    -r, --request FILE       Specify a Burp request file.
    -h, --help               Display help information.
    
## Contributing

If you'd like to contribute, please follow these guidelines.

1. Fork the project.
2. Create a new branch.
3. Make your changes.
4. Open a pull request.

## License

This project is free to use and modify to your liking.
