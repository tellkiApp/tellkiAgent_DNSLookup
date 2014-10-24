//node dns_lookup_monitor.js 1438 "1,1" "1439" "www.google.pt#testChecker#A#172.194.34.242. www.google.pt#testChecker#A#" ""

//####################### EXCEPTIONS ################################

function InvalidParametersNumberError() {
    this.name = "InvalidParametersNumberError";
    this.message = ("Wrong number of parameters.");
}
InvalidParametersNumberError.prototype = Error.prototype;

function InvalidMetricStateError() {
    this.name = "InvalidMetricStateError";
    this.message = ("Invalid value in metric state.");
}
InvalidMetricStateError.prototype = Error.prototype;

function InvalidParametersError() {
    this.name = "InvalidParametersError";
    this.message = ("Invalid value in parameters.");
}
InvalidParametersError.prototype = Error.prototype;



// ############# INPUT ###################################

(function() {
	try
	{
		monitorInput(process.argv.slice(2));
	}
	catch(err)
	{	
		console.log(err.message);
		process.exit(1);
	}
}).call(this)



function monitorInput(args)
{
	
	if(args.length != 5)
	{
		throw new InvalidParametersNumberError()
	}		
	
	monitorInputProcess(args);
}


function monitorInputProcess(args)
{
	//metric state
	var metricState = args[1].replace("\"", "");
	
	var tokens = metricState.split(",");

	var checkStatus = false;
	var checkTimeout = false;
	
	if (tokens.length == 2)
	{
		if (tokens[0] == "1")
		{
			checkStatus = true;
		}

		if (tokens[1] == "1")
		{
			checkTimeout = true;
		}
	}
	else
	{
		throw new InvalidMetricStateError();
	}
	
	
	//metric state
	var cirUUDIS = args[2].replace("\"", "").split(",");
	
	// Requests.
	var portTestsRepresentation = args[3].replace("\"", "").split(",");
	
	var dnsQueryRequests = [];

	var i = 0;
	for (var j in portTestsRepresentation)
	{
		var tokens = portTestsRepresentation[j].split("#", 4);

		if (tokens.length == 4)
		{
			var portTestRepresentation = new Object();
			portTestRepresentation.cirUUDI = cirUUDIS[i];
			portTestRepresentation.record = tokens[2];
			portTestRepresentation.host = tokens[0];
			portTestRepresentation.ipMatch = tokens[3];
			portTestRepresentation.checkStatus = checkStatus;
			portTestRepresentation.checkTimeout = checkTimeout;
			
			dnsQueryRequests.push(portTestRepresentation);
		}
		else
		{
			throw new InvalidParametersError();
		}

		i++;
	}
	
	
	monitorDNSLookup(dnsQueryRequests);
	
}




//################### OUTPUT ###########################

function output(metrics, targetId)
{
	var out = "";
	
	for(var i in metrics)
	{
		var metric = metrics[i];
		
		out += new Date(metric.ts).toISOString();
		out += "|";
		out += targetId;
		out += "|";
		out += metric.id;
		out += "|";
		out += metric.val
		out += "|";
		out += metric.obj
		out += "\n";
		
	}
	console.log(out);
}



// ################# MONITOR ###########################
//unction getDNS(msg, mon, t, callback)
function monitorDNSLookup(dnsQueryRequests) 
{

	//console.log(JSON.stringify(dnsQueryRequests))
	
    this.resolveDNS = function resolveDNS(dnsQueryRequest, callback) {
        var dns = require("dns");
        if (dnsQueryRequest != undefined) {
            dns.resolve(dnsQueryRequest.host, dnsQueryRequest.record, function (err, addresses) {
                var result = 0;
                if (err) {
                    //if (err.errno == dns.NODATA)
                    //    sys.puts("No A entry for " + conf[2]);
                    //else
                    //    throw err;
                } else {
                    if (dnsQueryRequest.ipMatch === '')
                        result = 1;
                    else
                        if (dnsQueryRequest.record === 'MX') {
                            for (var i in addresses) {
                                if (addresses[i].exchange.indexOf(dnsQueryRequest.ipMatch) != -1) {
                                    result = 1;
                                    break;
                                }
                            }
                        } else
                            if (addresses.indexOf(dnsQueryRequest.ipMatch) != -1) {
                                //console.log("addresses " + dnsQueryRequest.ipMatch + ":" + addresses);
                                result = 1;
                            }

                    if (result === 0)
                    {
						//console.log("fail: " + dnsQueryRequest.ipMatch + "!=" + addresses);
					}
                }
                callback(result, dnsQueryRequest);
            });
        }
    }

    //var items = mon.MonitorConfig.split(',');
    for (var i in dnsQueryRequests) {
        //Test Name
        var _dnsQueryRequest = dnsQueryRequests[i];
        
		(function (dnsQueryRequest) {
            var start = Date.now();
            this.resolveDNS(dnsQueryRequest, function (result, _dnsQueryRequest) {
                metrics = [];
                if (result == 1) {
                    //Status
                    if (_dnsQueryRequest.checkStatus) {
                        var metric = new Object();
                        metric.id = '165:9';
                        metric.val = '1';
                        metric.ts = start;
                        metric.exec = Date.now() - start;
                        metric.obj = _dnsQueryRequest.host;
						
                        metrics.push(metric);
                    }
                    //Response Time
                    if (_dnsQueryRequest.checkTimeout) {
                        var metric = new Object();
                        metric.id = '124:7';
                        metric.val = Date.now() - start;
                        metric.ts = start;
                        metric.exec = Date.now() - start;
                        metric.obj = _dnsQueryRequest.host;
						
                        metrics.push(metric)
                    }

                    output(metrics, _dnsQueryRequest.cirUUDI);
					
                } else {
                    //console.log('NOK');
                    var metric = new Object();
                    //Status
                    metric.id = '165:9';
                    metric.val = '0';
                    metric.ts = start;
                    metric.exec = Date.now() - start;
                    metric.obj = _dnsQueryRequest.host;
					
                    metrics.push(metric);
					
                    output(metrics, _dnsQueryRequest.cirUUDI);
                }
            });
        })(_dnsQueryRequest);
    }
}
