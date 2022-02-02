"""
Dash port of Shiny iris k-means example:

https://shiny.rstudio.com/gallery/kmeans-example.html
"""
import dash
import dash_bootstrap_components as dbc
import dash_core_components as dcc
import dash_html_components as html
import pandas as pd
import plotly.graph_objs as go
from dash.dependencies import Input, Output
from sklearn import datasets
from sklearn.cluster import KMeans
import plotly.graph_objs as go
import dash_daq as daq
import psutil
from collections import deque
import time
import plotly.graph_objs as go
import plotly

startTime = time.time()


X = deque(maxlen = 20)
Y = deque(maxlen = 20)

X1 = deque(maxlen = 20)
Y1 = deque(maxlen = 20)

from numpy import random
global ANOMALIES
ANOMALIES = []
def anomaly_generator():
    comms = ["malware1","malware2","malware3","malware4","malware5"]
    PID = random.randint(40000)
    comm = comms[random.randint(len(comms))]
    return(PID,comm)

for i in range(0,2):
    ANOMALIES.append(anomaly_generator())

external_stylesheet = [
    dbc.themes.PULSE
   
]
app = dash.Dash(external_stylesheets= external_stylesheet)




SIDEBAR_STYLE = {
    "position": "fixed",
    "top": 0,
    "left": 0,
    "bottom": 0,
    "width": "32rem",
    "padding": "2rem 1rem",
    "overflow-y":"scroll",
    "scroll":":::-webkit-scrollbar-thumb:hover {background: #555; }",
    "background-color": "#ffffff",
    
}

CONTENT_STYLE = {
    "position":"fixed",
    "height":"15%",
    "width":"85%",
    "left":"34rem",
    "margin-bottom":"10%",
    "padding": "2rem 1rem",
}

def generate_list():
    global ANOMALIES
    return dbc.ListGroup(
        [ 
            dbc.ListGroupItem(
            [
                dbc.ListGroupItemHeading(str(PID)),
                dbc.ListGroupItemText(str(comm)),
            ],
            color="danger") for (PID,comm) in ANOMALIES
            
        ],
        flush=True
    )

navbar = dbc.NavbarSimple(
    brand="NavbarSimple",
    brand_href="#",
    color="primary",
    dark=True,
    fluid=True,
    style={"height":"100%"}
)

sidebar = html.Div(
    [
        html.H2("ANOMALIES", className="display-4"),
        html.Hr(),
        html.H6( 
            "List of anomalies detected"
        ),
        dbc.Nav(
            
            dbc.Card(
        [
           dbc.CardHeader("ANOMALIES"),
           dbc.CardBody
           (
            [
                generate_list()
            ]
           )
        ],
           id="anomaly-list", body=True,
                    ),
            vertical=True,
            pills=True,
        ),
    ],
    style=SIDEBAR_STYLE,
)
intrusions = dbc.Card(

    [
        dbc.CardBody([
            html.H2("ANOMALIES DETECTED", className="card-text"),
            html.H3(html.Div(id='anomalies-output'),)
        ])

    ],style={"height":"100%"}
),
traces = dbc.Card(

     [
        dbc.CardBody([
            html.H2("TRACES ANALYZED ", className="card-text"),
           html.H3(html.Div(id='traces-output'),)
        ],style={"height":"100%","width":"100%", "align":"left"})

    ],style={"height":"100%","align":"left"}
),
ramStats = dbc.Card(
[
    html.H3("RAM USAGE"),
    daq.Gauge(
    id="ram-percentage",
    showCurrentValue=True,
    units="MPH",
    value=0,
    label='Default',
    max=100,
    min=0,
    ),
        dcc.Graph(id = 'ram-graph',
                  animate = True
                  )
]
),
cpuStats = dbc.Card([

    html.H3("CPU %"),
    daq.Gauge(
    id="cpu-percentage",
    showCurrentValue=True,
    units="MPH",
    value=0,
    label='Default',
    max=100,
    min=0,
    ),
    dcc.Graph(id = 'cpu-graph',
                  animate = True)                  
]
),


content = html.Div(
                        [
                        
                        dbc.Row([dbc.Col(intrusions), dbc.Col(traces)],  style={"height":"35%"}),
                        html.Br(),
                        html.Br(),
                        html.Br(),
                        html.Br(),
                        html.Br(),
                        html.Br(),
                        html.Br(),
                        dbc.Row([dbc.Col(ramStats), dbc.Col(cpuStats)]),
                        ],
                                        
                    id="page-content", 
                    style=CONTENT_STYLE
                )


app.layout = html.Div(
    [
        
         dcc.Interval(
            id='interval-component',
            interval=1*3000, # in milliseconds
            n_intervals=0
        ),
        html.Div(navbar),
        html.Br(),
        sidebar,
        content
    ]
)



def add_to_anomalies_list(n):
        ANOMALIES.append(anomaly_generator())
        return generate_list()

app.callback( Output(component_id='anomaly-list', component_property='children'),
                [Input(component_id='interval-component', component_property='n_intervals')])(
    add_to_anomalies_list
)




@app.callback( Output(component_id='ram-percentage', component_property='value'),
                Input(component_id='interval-component', component_property='n_intervals')
            )            
def update_ram_percentage(n):
    return psutil.virtual_memory().percent

@app.callback( Output(component_id='cpu-percentage', component_property='value'),
                Input(component_id='interval-component', component_property='n_intervals')
            )            
def update_cpu_percentage(n):
    return psutil.cpu_percent(None, percpu=False)

@app.callback( Output(component_id='ram-graph', component_property='figure'),
                Input(component_id='interval-component', component_property='n_intervals')
                )


def update_ram_graph(n):
    Y.append(psutil.virtual_memory().percent)
    X.append(time.time() - startTime)
    data = plotly.graph_objs.Scatter(
            x=list(X),
            y=list(Y),
            name='Scatter',
            mode= 'lines+markers'
    )
    return {'data': [data],
            'layout' : go.Layout(xaxis=dict(
                    range=[min(X),max(X)+10]),yaxis = 
                    dict(range = [min(Y)-2,max(Y)+2]),
                    )}


@app.callback( Output(component_id='cpu-graph', component_property='figure'),
                Input(component_id='interval-component', component_property='n_intervals')
                )


def update_cpu_graph(n):
    Y1.append(psutil.cpu_percent(None, percpu=False))
    X1.append(time.time() - startTime)
    data = plotly.graph_objs.Scatter(
            x=list(X1),
            y=list(Y1),
            name='Scatter',
            mode= 'lines+markers'
    )

    return {'data': [data],
            'layout' : go.Layout(xaxis=dict(
                    range=[min(X1),max(X1)+10]),yaxis = 
                    dict(range = [min(Y1)-2,max(Y1)+2]),
                    )}
    
@app.callback( Output(component_id='traces-output', component_property='children'),
                Input(component_id='interval-component', component_property='n_intervals')
            ) 
def update_traces_no(n):
    return html.H2(n)         

@app.callback( Output(component_id='anomalies-output', component_property='children'),
                Input(component_id='interval-component', component_property='n_intervals')
            ) 
def update_traces_no(n):
    return html.H2(n)      


if __name__ == "__main__":
    app.run_server(debug=True, port=8888)