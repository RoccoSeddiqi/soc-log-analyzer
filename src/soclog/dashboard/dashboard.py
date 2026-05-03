import json
import os
import sys
import pandas as pd
import plotly.express as px
from dash import Dash, html, dcc, dash_table


def load_json_file(path):
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def make_card(title, value, color):
    return html.Div(
        [
            html.Div(title, style={
                "fontSize": "14px",
                "color": "#9CA3AF",
                "marginBottom": "8px"
            }),
            html.Div(str(value), style={
                "fontSize": "30px",
                "fontWeight": "bold",
                "color": color
            }),
        ],
        style={
            "backgroundColor": "#111827",
            "border": "1px solid #1F2937",
            "borderRadius": "14px",
            "padding": "20px",
            "boxShadow": "0 4px 12px rgba(0,0,0,0.25)",
            "flex": "1",
            "minWidth": "180px"
        }
    )


report_path = sys.argv[1] if len(sys.argv) > 1 else "output/report.json"
dataset_path = sys.argv[2] if len(sys.argv) > 2 else "output/normalized_events.json"

report_data = load_json_file(report_path)
dataset_data = load_json_file(dataset_path)

app = Dash(__name__)

if report_data is None:
    app.layout = html.Div(
        [
            html.H1("LogMentor Dashboard", style={"color": "white"}),
            html.P(f"No report data found at: {report_path}", style={"color": "#D1D5DB"})
        ],
        style={
            "backgroundColor": "#0B1220",
            "minHeight": "100vh",
            "padding": "30px",
            "fontFamily": "Arial, sans-serif"
        }
    )
else:
    total_alerts = report_data.get("total_alerts", 0)
    severity_counts = report_data.get("severity_counts", {})
    category_counts = report_data.get("category_counts", {})
    rule_counts = report_data.get("rule_counts", {})
    alerts = report_data.get("alerts", [])

    high_count = severity_counts.get("HIGH", 0)
    medium_count = severity_counts.get("MEDIUM", 0)
    low_count = severity_counts.get("LOW", 0)

    severity_df = pd.DataFrame(list(severity_counts.items()), columns=["Severity", "Count"])
    category_df = pd.DataFrame(list(category_counts.items()), columns=["Category", "Count"])
    rule_df = pd.DataFrame(list(rule_counts.items()), columns=["Rule", "Count"])
    alerts_df = pd.DataFrame(alerts)

    dataset_df = pd.DataFrame(dataset_data) if dataset_data else pd.DataFrame()

    if not alerts_df.empty:
        preferred_cols = [
            "rule_name", "severity", "category", "host",
            "user", "event_id", "command_line", "reason",
            "educational_note", "recommended_action"
        ]
        existing_cols = [col for col in preferred_cols if col in alerts_df.columns]
        alerts_df = alerts_df[existing_cols]

    severity_fig = px.bar(severity_df, x="Severity", y="Count", title="Alerts by Severity")
    category_fig = px.bar(category_df, x="Category", y="Count", title="Alerts by Category")
    rule_fig = px.bar(rule_df, x="Rule", y="Count", title="Rule Hits")

    for fig in [severity_fig, category_fig, rule_fig]:
        fig.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font_color="white",
            title_font_size=18,
            margin=dict(l=20, r=20, t=50, b=40)
        )

    overview_tab = html.Div(
        [
            html.Div(
                [
                    make_card("Total Alerts", total_alerts, "#FFFFFF"),
                    make_card("High Severity", high_count, "#EF4444"),
                    make_card("Medium Severity", medium_count, "#F59E0B"),
                    make_card("Low Severity", low_count, "#10B981"),
                ],
                style={
                    "display": "flex",
                    "gap": "20px",
                    "flexWrap": "wrap",
                    "marginBottom": "30px"
                }
            ),
            html.Div(
                [
                    html.Div(
                        dcc.Graph(figure=severity_fig),
                        style={
                            "backgroundColor": "#111827",
                            "padding": "15px",
                            "borderRadius": "14px",
                            "flex": "1",
                            "minWidth": "400px"
                        }
                    ),
                    html.Div(
                        dcc.Graph(figure=category_fig),
                        style={
                            "backgroundColor": "#111827",
                            "padding": "15px",
                            "borderRadius": "14px",
                            "flex": "1",
                            "minWidth": "400px"
                        }
                    ),
                ],
                style={
                    "display": "flex",
                    "gap": "20px",
                    "flexWrap": "wrap",
                    "marginBottom": "30px"
                }
            ),
            html.Div(
                dcc.Graph(figure=rule_fig),
                style={
                    "backgroundColor": "#111827",
                    "padding": "15px",
                    "borderRadius": "14px"
                }
            )
        ]
    )

    alerts_tab = html.Div(
        [
            html.H2("Alert Details + Analyst Learning Notes", style={"color": "white", "marginBottom": "15px"}),
            html.P(
                "Educational notes explain why each alert matters and what an entry-level SOC analyst should check next.",
                style={"color": "#9CA3AF", "marginBottom": "15px"}
            ),
            dash_table.DataTable(
                data=alerts_df.to_dict("records") if not alerts_df.empty else [],
                columns=[{"name": col, "id": col} for col in alerts_df.columns] if not alerts_df.empty else [],
                page_size=10,
                style_table={"overflowX": "auto"},
                style_cell={
                    "backgroundColor": "#111827",
                    "color": "white",
                    "border": "1px solid #1F2937",
                    "textAlign": "left",
                    "padding": "10px",
                    "maxWidth": "250px",
                    "whiteSpace": "normal"
                },
                style_header={
                    "backgroundColor": "#1F2937",
                    "color": "white",
                    "fontWeight": "bold"
                }
            )
        ],
        style={
            "backgroundColor": "#111827",
            "padding": "20px",
            "borderRadius": "14px"
        }
    )

    dataset_tab = html.Div(
        [
            html.H2("Normalized Dataset", style={"color": "white", "marginBottom": "15px"}),
            html.P(
                f"Rows loaded: {len(dataset_df)}",
                style={"color": "#9CA3AF", "marginBottom": "15px"}
            ),
            dash_table.DataTable(
                data=dataset_df.head(100).to_dict("records") if not dataset_df.empty else [],
                columns=[{"name": col, "id": col} for col in dataset_df.columns] if not dataset_df.empty else [],
                page_size=15,
                filter_action="native",
                sort_action="native",
                style_table={"overflowX": "auto"},
                style_cell={
                    "backgroundColor": "#111827",
                    "color": "white",
                    "border": "1px solid #1F2937",
                    "textAlign": "left",
                    "padding": "10px",
                    "maxWidth": "250px",
                    "whiteSpace": "normal"
                },
                style_header={
                    "backgroundColor": "#1F2937",
                    "color": "white",
                    "fontWeight": "bold"
                }
            )
        ],
        style={
            "backgroundColor": "#111827",
            "padding": "20px",
            "borderRadius": "14px"
        }
    )

    app.layout = html.Div(
        [
            html.Div(
                [
                    html.H1("LogMentor Dashboard", style={
                        "color": "white",
                        "marginBottom": "6px"
                    }),
                    html.P("Security alert summary and dataset review.", style={
                        "color": "#9CA3AF",
                        "marginTop": "0"
                    }),
                ],
                style={"marginBottom": "25px"}
            ),

            dcc.Tabs(
                children=[
                    dcc.Tab(label="Overview", children=[overview_tab], style={
                        "backgroundColor": "#1F2937",
                        "color": "white",
                        "padding": "10px"
                    }, selected_style={
                        "backgroundColor": "#111827",
                        "color": "white",
                        "padding": "10px",
                        "fontWeight": "bold"
                    }),
                    dcc.Tab(label="Alerts", children=[alerts_tab], style={
                        "backgroundColor": "#1F2937",
                        "color": "white",
                        "padding": "10px"
                    }, selected_style={
                        "backgroundColor": "#111827",
                        "color": "white",
                        "padding": "10px",
                        "fontWeight": "bold"
                    }),
                    dcc.Tab(label="Dataset", children=[dataset_tab], style={
                        "backgroundColor": "#1F2937",
                        "color": "white",
                        "padding": "10px"
                    }, selected_style={
                        "backgroundColor": "#111827",
                        "color": "white",
                        "padding": "10px",
                        "fontWeight": "bold"
                    }),
                ]
            )
        ],
        style={
            "backgroundColor": "#0B1220",
            "minHeight": "100vh",
            "padding": "30px",
            "fontFamily": "Arial, sans-serif"
        }
    )

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=8050)