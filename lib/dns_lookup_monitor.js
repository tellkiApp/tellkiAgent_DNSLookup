
var metricStatusId = '165:Status:9';
var metricResponseTimeId = '124:Response Time:7';

//####################### EXCEPTIONS ################################

function InvalidParametersNumberError() {
    this.name = "InvalidParametersNumberError";
    this.message = "Wrong number of parameters.";
	this.code = 3;
}
InvalidParametersNumberError.prototype = Object.create(Error.prototype);
InvalidParametersNumberError.prototype.constructor = InvalidParametersNumberError;

function InvalidMetricStateError() {
    this.name = "InvalidMetricStateError";
    this.message = "Invalid value in metric state.";
	this.code = 9;
}
InvalidMetricStateError.prototype = Object.create(Error.prototype);
InvalidMetricStateError.prototype.constructor = InvalidMetricStateError;

function InvalidParametersError() {
    this.name = "InvalidParametersError";
    this.message = "Invalid value in parameters.";
	this.code = 10;
}
InvalidParametersError.prototype = Object.create(Error.prototype);
InvalidParametersError.prototype.constructor = InvalidParametersError;



// ############# INPUT ###################################

(function() {
	try
	{
		monitorInput(process.argv.slice(2));
	}
	catch(err)
	{	
		if(err instanceof InvalidParametersNumberError)
		{
			console.log(err.message);
			process.exit(err.code);
		}
		else if(err instanceof InvalidMetricStateError)
		{
			console.log(err.message);
			process.exit(err.code);
		}
		else if(err instanceof InvalidParametersError)
		{
			console.log(err.message);
			process.exit(err.code);
		}
		else
		{
			console.log(err.message);
			process.exit(1);
		}
	}
}).call(this)



function monitorInput(args)
{
	
	if(args.length != 3)
	{
		throw new InvalidParametersNumberError()
	}		
	
	monitorInputProcess(args);
}


function monitorInputProcess(args)
{
	//metric state
	var metricState = args[0];
	
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
	
	
	//cirIds
	var cirUUDIS = args[1].split(",");
	
	// Requests.
	var portTestsRepresentation = args[2].split(",");
	
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
			portTestRepresentation.host = tokens[0].split(";")[1];
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

	for(var i in metrics)
	{
		var out = "";
		var metric = metrics[i];
		
		out += targetId;
		out += "|";
		out += metric.id;
		out += "|";
		out += metric.val
		out += "|";
		out += metric.obj
		out += "|";
		
		console.log(out);
	}
	
}



// ################# MONITOR ###########################

function monitorDNSLookup(dnsQueryRequests) 
{	
    this.resolveDNS = function resolveDNS(dnsQueryRequest, callback) {
        var dns = require("dns");
        if (dnsQueryRequest != undefined) {
            dns.resolve(dnsQueryRequest.host, dnsQueryRequest.record, function (err, addresses) {
                var result = 0;
                if (!err) 
				{
                    if (dnsQueryRequest.ipMatch === '')
                    {
						result = 1;
                    }
					else
                    {
						if (dnsQueryRequest.record === 'MX') 
						{
                            for (var i in addresses) {
                                if (addresses[i].exchange.indexOf(dnsQueryRequest.ipMatch) != -1) {
                                    result = 1;
                                    break;
                                }
                            }
                        } 
						else
                        {
							if (addresses.indexOf(dnsQueryRequest.ipMatch) != -1) 
							{
                                result = 1;
                            }
						}
					}
				}		
				
				callback(result, dnsQueryRequest);
				
            });
        }
    }

	
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
                        metric.id = metricStatusId;
                        metric.val = '1';
                        metric.ts = start;
                        metric.exec = Date.now() - start;
                        metric.obj = _dnsQueryRequest.host;
						
                        metrics.push(metric);
                    }
                    //Response Time
                    if (_dnsQueryRequest.checkTimeout) {
                        var metric = new Object();
                        metric.id = metricResponseTimeId;
                        metric.val = Date.now() - start;
                        metric.ts = start;
                        metric.exec = Date.now() - start;
                        metric.obj = _dnsQueryRequest.host;
						
                        metrics.push(metric)
                    }

                    output(metrics, _dnsQueryRequest.cirUUDI);
					
                } else {
                    var metric = new Object();
                    //Status
                    metric.id = metricStatusId;
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
