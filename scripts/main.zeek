module pcr_field;

redef record Conn::Info += {
	pcr: double &optional &log;
};

event connection_state_remove(c: connection)
	{
	#c$conn$orig_bytes is type of count

	if ( c$id$orig_h !in Site::local_nets )
		return;

	local total_orig_bytes: double = c$orig$size;
	local total_resp_bytes: double = c$resp$size;

	local mone: double = total_orig_bytes - total_resp_bytes;
	local mechane: double = total_orig_bytes + total_resp_bytes;

	if ( mechane == 0 )
		return;

	c$conn$pcr = ( mone ) / ( mechane );
	}
