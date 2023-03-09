package postee.rawmessage.json

################################################ Templates ################################################
#main template to render message

tpl:=`
h1. Image Metadata

||Name||Namespace||CreationTimestamp||Registry||Repository||Tag||
| %s | %s | %s | %s | %s | %s |

h1. Resource Information

||Used By Pod||Container Name||Resource Kind||
| %s | %s | %s |

h1. Vulnerability Summary
||CRITICAL||HIGH||MEDIUM||LOW||UNKNOWN||NONE||
| %d | %d | %d | %d | %d | %d |

h1. Vulnerabilities

%s

%s

`

vlnrb_tpl = `
h2. %s severity vulnerabilities
%s
`
#Extra % is required in width:100%

table_tpl := `
%s
`

cell_tpl := `| %s `

header_tpl := `|| %s `

row_tpl := `
| %s `

colored_text_tpl := "{color:%s}%s{color}"

###########################################################################################################

############################################## Html rendering #############################################

render_table_headers(headers) = row {
    count(headers) > 0
    ths := [th |
        header := headers[_]
        th := sprintf(header_tpl, [header])
    ]

    row := sprintf(row_tpl, [concat("", ths)])
}

render_table_headers(headers) = "" { #if headers not specified return empty results
    count(headers) == 0
}

render_table(headers, content_array) = s {
    rows := [tr |
        cells := content_array[_]
        tds := [td |
            ctext := cells[_]
            td := to_cell(ctext)
        ]

        tr = sprintf(row_tpl, [concat("", tds)])
    ]

    s := sprintf(table_tpl, [concat("", array.concat([render_table_headers(headers)], rows))])
}

to_cell(txt) = c {
    c := sprintf(cell_tpl, [txt])
}


####################################### Template specific functions #######################################


cnt_by_severity(severity) = cnt {
    vln_list := [r |
        some i
        item := input.report.vulnerabilities[i]

        item.severity == severity

        r := item.vulnerabilityID
    ]

    cnt := count(vln_list)
}

# builds 2-dimension array for vulnerability table
vln_list(severity) = vlnrb {
    some j
	vlnrb := [r |
                    item := input

                    vulnerability := item.report.vulnerabilities
                    VulnerabilityID := vulnerability[j].vulnerabilityID
                    Resource := vulnerability[j].resource
                    InstalledVersion := vulnerability[j].installedVersion
                    FixedVersion := vulnerability[j].fixedVersion
                    Severity := vulnerability[j].severity
                    Title := vulnerability[j].title
                    PrimaryLink := vulnerability[j].primaryLink

                    Severity == severity # only items with severity matched
                    r := [VulnerabilityID, Resource, InstalledVersion, FixedVersion, Severity, Title, PrimaryLink]
              ]
}

vlnrb_headers := ["VulnerabilityID", "Resource","InstalledVersion", "FixedVersion", "Severity", "Title", "PrimaryLink"]

render_vlnrb(severity, list) = sprintf(vlnrb_tpl, [severity, render_table(vlnrb_headers, list)]) {
    count(list) > 0
}

render_vlnrb(severity, list) = "" {  #returns empty string if list of vulnerabilities is passed
    count(list) == 0
}

##########################Jira Ticket Content#################################################################################
title:=sprintf("Trivy Operator VulnerabilityReport for Image %s:%s", [input.report.artifact.repository, input.report.artifact.tag])

result = msg {

    msg := sprintf(tpl, [
    input.metadata.name,
    input.metadata.namespace,
    input.metadata.creationTimestamp,
    input.report.registry.server,
    input.report.artifact.repository,
    input.report.artifact.tag,
    input.metadata.labels.trivy-operator.resource.name,
    input.metadata.labels.trivy-operator.container.name,
    input.metadata.labels.trivy-operator.resource.kind,
    input.report.summary.criticalCount,
    input.report.summary.highCount,
    input.report.summary.mediumCount,
    input.report.summary.lowCount,
    input.report.summary.unknownCount,
    input.report.summary.noneCount,
    render_vlnrb("Critical", vln_list("CRITICAL")),
    render_vlnrb("HIGH", vln_list("HIGH"))
    ])
}
