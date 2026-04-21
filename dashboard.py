import pandas as pd
import requests
import plotly.express as px
from dash import Dash, html, Input, Output, dcc
from zipfile import ZipFile
from io import BytesIO

exe_url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/psh_python_webserver.zip'
cred_url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip'

zipFileRequest = requests.get(exe_url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath_exe = zipFile.extract(zipFile.namelist()[0])

zipFileRequest = requests.get(cred_url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath_cred = zipFile.extract(zipFile.namelist()[0])

# Storing logs into a dataframe
exe_df = pd.read_json(path_or_buf=datasetJSONPath_exe, lines=True)
cred_df = pd.read_json(path_or_buf=datasetJSONPath_cred, lines=True)

dashboard = Dash()

dashboard.layout = html.Div(children=["Dashboard"])

if __name__ == '__main__':
    dashboard.run(debug=True)
