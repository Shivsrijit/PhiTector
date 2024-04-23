## Phishing Detector

### Project Description
This project aims to detect phishing websites using machine learning techniques. We trained our model on a synthetic Kaggle dataset and deployed it on both a Streamlit web page and a Chromium extension, which makes it compatible with major browsers like Chrome, Edge, Opera, Brave etc. and would help the average consumer in identifying potential phishing websites.

Submission for CIA-2 for Foundations of Data Science, Semester 2, 2023-27 batch.

### Team Phishermen
- [Shivsrijit](https://github.com/shivsrijit/)
- [Raghav Sridharan](https://github.com/raghavsridharan)
- [Saran Shankar](https://github.com/try3d/)
- [Prajesh Raam](https://github.com/hotaru-hspr)


### Tech Stack
- Pandas
- Numpy
- Matplotlib
- Scikit-Learn
- SQLite
- Streamlit
- Manifest v2 (Chromium extension)
- FastAPI

### Requirements
Install the required modules by running the following command after cd'ing to the working folder.

```pip install -r requirements.txt```

### Running the program
#### Streamlit:
Run the Streamlit file by using either of these commands:

```python -m streamlit run streamlit_app.py```

or

```streamlit run streamlit_app.py```

#### Chromium Extension:
1. Load the extension files to your Chromium-based browser by using the "Load unpacked extension" in settings.
2. Run main.py in the background.
3. Open a website and click on the extension's icon.
4. Once processed, the percentage of legitimacy of the website will be displayed.
