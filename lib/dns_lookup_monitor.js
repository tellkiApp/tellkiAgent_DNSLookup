/**
* This script was developed by Guberni and is part of Tellki's Monitoring Solution
*
* February, 2015
* 
* Version 1.0
* 
* DESCRIPTION: Monitor DNS Lookup utilization
*
* SYNTAX:  node dns_lookup_monitor.js <METRIC_STATE> <CIR_IDS> <PARAMS>
* 
* EXAMPLE: node dns_lookup_monitor.js "1,1" "2781" "new;gmail.com#new#MX#"
*
* README:
*		<METRIC_STATE> is generated internally by Tellki and it's only used by Tellki default monitors.
*		1 - metric is on ; 0 - metric is off
*
*		<CIR_IDS> is generated internally by Tellki and its only used by Tellki default monitors
*
*		<PARAMS> are 4 fields separeted by "#" and it contains the monitor's configuration, is generated internally
*		by Tellki and it's only used by Tellki's default monitors.
**/


// METRICS IDS
var metricStatusId = '165:Status:9';
var metricResponseTimeId = '124:Response Time:4';




// ############# INPUT ###################################

//START
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
		else
		{
			console.log(err.message);
			process.exit(1);
		}
	}
}).call(this)



/*
* Verify number of passed arguments into the script.
*/
function monitorInput(args)
{
	
	if(args.length != 3)
	{
		throw new InvalidParametersNumberError()
	}		
	
	monitorInputProcess(args);
}


/*
* Process the passed arguments and send them to monitor execution (monitorDNSLookup)
* Receive: arguments to be processed
*/
function monitorInputProcess(args)
{
	//<METRIC_STATE>
	var metricState = args[0];
	
	var tokens = metricState.split(",");

	// metric Status state
	var checkStatus = false;
	// metric Response time state
	var checkTimeout = false;
	
	if (tokens[0] == "1")
	{
		checkStatus = true;
	}

	if (tokens[1] == "1")
	{
		checkTimeout = true;
	}
	
	
	//<CIR_IDS>
	var cirUUDIS = args[1].split(",");
	
	// <PARAMS>
	var portTestsRepresentation = args[2].split(",");
	
	var dnsQueryRequests = [];

	//create dns tests
	var i = 0;
	for (var j in portTestsRepresentation)
	{
		var tokens = portTestsRepresentation[j].split("#", 4);

		var portTestRepresentation = new Object();
		portTestRepresentation.cirUUDI = cirUUDIS[i];
		portTestRepresentation.record = tokens[2];
		portTestRepresentation.host = tokens[0].split(";")[1];
		portTestRepresentation.ipMatch = tokens[3];
		portTestRepresentation.checkStatus = checkStatus;
		portTestRepresentation.checkTimeout = checkTimeout;
		
		dnsQueryRequests.push(portTestRepresentation);
		
		i++;
	}
	
	//call monitor
	monitorDNSLookup(dnsQueryRequests);
	
}



// ################# DNS LOOKUP ###########################

/*
* Retrieve metrics information.
* Receive: Test's list
*/
function monitorDNSLookup(dnsQueryRequests) 
{	

	/*
	* DNS Resolver.
	* Receive:
	* - dns test
	* - callback function to be exectuted after dns test
	*/
    this.resolveDNS = function resolveDNS(dnsQueryRequest, callback) {
        var dns = require("dns");
        if (dnsQueryRequest != undefined) {
			//resolve dns
            dns.resolve(dnsQueryRequest.host, dnsQueryRequest.record, function (err, addresses) {
                var result = 0;
                if (!err) 
				{
					//compare with ip in configuration if not empty
                    if (dnsQueryRequest.ipMatch === '')
                    {
						result = 1;
                    }
					else
                    {
						//dns record verification
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

        var _dnsQueryRequest = dnsQueryRequests[i];
        
		/*
		* Tests executer.
		* Receive: dns test.
		*/
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


//################### OUTPUT METRICS ###########################
/*
* Send metrics to console
* Receive: 
* - metrics list to output 
* - target id (cir_id representing the dns test)
*/
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



//####################### EXCEPTIONS ################################

//All exceptions used in script

function InvalidParametersNumberError() {
    this.name = "InvalidParametersNumberError";
    this.message = "Wrong number of parameters.";
	this.code = 3;
}
InvalidParametersNumberError.prototype = Object.create(Error.prototype);
InvalidParametersNumberError.prototype.constructor = InvalidParametersNumberError;
