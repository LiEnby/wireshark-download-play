-- Opcode on :10
dlplay = Proto("DSDOWNLOADPLAY", "Nintendo DS Download Play")

-- requests 

-- opcode
local t_magic = ProtoField.uint8("dlplay.magic", "Magic", base.HEX)
local t_flag = ProtoField.uint8("dlplay.flag", "Flag", base.DEC)
local t_port = ProtoField.uint8("dlplay.port", "Port", base.DEC)
local t_opcode = ProtoField.uint8("dlplay.opcode", "Opcode", base.HEX)
local t_seq = ProtoField.uint8("dlplay.seq", "Sequence", base.DEC)

-- get name packet
local t_bytelen = ProtoField.uint8("dlplay.bytelen", "Name Length (bytes)", base.HEX)
local t_strlen = ProtoField.uint8("dlplay.strlen", "Name Length (characters)", base.HEX)
local t_name = ProtoField.string("dlplay.name", "Name", base.UNICODE)

-- get nds rom
local t_offset = ProtoField.uint16("dlplay.offset", "Offset", base.HEX)

-- response
local t_resp_magic = ProtoField.uint32("dlplay.resp.magic", "Magic", base.HEX)
local t_resp_flag = ProtoField.uint8("dlplay.resp.flag", "Flag", base.HEX)
local t_resp_port = ProtoField.uint8("dlplay.resp.port", "Port", base.HEX)
local t_resp_opcode = ProtoField.uint16("dlplay.resp.opcode", "Opcode", base.HEX)
local t_resp_seq = ProtoField.uint8("dlplay.resp.Id", "Id", base.DEC)
local t_resp_footer = ProtoField.uint16("dlplay.resp.footer", "Footer", base.HEX)

-- nds rom recevied
local t_resp_offset = ProtoField.uint32("dlplay.resp.offset", "Offset", base.HEX)

-- signature received

local t_sign_arm9_entry = ProtoField.uint32("dlplay.sign.arm9_entry", "Arm9 Entrypoint", base.HEX)
local t_sign_arm7_entry = ProtoField.uint32("dlplay.sign.arm7_entry", "Arm7 Entrypoint", base.HEX)	

local t_sign_header_dest_tmp = ProtoField.uint32("dlplay.sign.header_dest_tmp", "Header Temp Memory Location", base.HEX)
local t_sign_header_dest = ProtoField.uint32("dlplay.sign.header_dest", "Header Memory Location", base.HEX)
local t_sign_header_len = ProtoField.uint32("dlplay.sign.header_len", "Header Length", base.HEX)

local t_sign_arm9_dest_tmp = ProtoField.uint32("dlplay.sign.arm9_dest_tmp", "Arm9 Temp Memory Location", base.HEX)
local t_sign_arm9_dest = ProtoField.uint32("dlplay.sign.arm9_dest", "Arm9 Memory Location", base.HEX)
local t_sign_arm9_size = ProtoField.uint32("dlplay.sign.arm9_dest_len", "Arm9 Length", base.HEX)

local t_sign_arm7_dest_tmp = ProtoField.uint32("dlplay.sign.header_arm7_dest_tmp", "Arm7 Temp Memory Location", base.HEX)
local t_sign_arm7_dest = ProtoField.uint32("dlplay.sign.header_arm7_dest", "Arm7 Memory Location", base.HEX)
local t_sign_arm7_size = ProtoField.uint32("dlplay.sign.header_arm7_size", "Arm7 Length", base.HEX)

local t_sign_rsa_header_end = ProtoField.uint32("dlplay.sign.rsa_end", "End of RSA Signature", base.HEX)
local t_sign_rsa = ProtoField.bytes("dlplay.sign.rsa_signature", "RSA Signature")

-- keepalive
local t_random = ProtoField.uint32("dlplay.random", "Random", base.HEX)

-- strings
local request_string = "DS -> Station"
local response_string = "Station -> DS"


dlplay.fields = {
	-- requests:
    t_magic, t_flag, t_port, t_opcode, t_seq, -- REQUEST packet general
	t_bytelen, t_strlen, t_name, -- SEND_DS_NAME packet
	t_offset, -- GET_NDS_ROM
	t_random, -- KeepAlive packet
	
	-- responses:
	t_resp_magic, t_resp_flag, t_resp_port, t_resp_opcode, t_resp_seq, t_resp_footer, -- RESPONSE packets
	t_resp_offset, -- DOWNLOAD_NDS_ROM
	
	t_sign_arm9_entry, t_sign_arm7_entry, t_sign_header_dest_tmp, t_sign_header_dest, t_sign_header_len, t_sign_arm9_dest_tmp, t_sign_arm9_dest, t_sign_arm9_size, t_sign_arm7_dest_tmp, t_sign_arm7_dest, t_sign_arm7_size, t_sign_rsa_header_end, t_sign_rsa -- RSA Signature Data
}

g_opcodes = {
	-- requests
	INITALIZE_DOWNLOAD = 0,
	SEND_DS_NAME = 7,
	AWAITING_RSA_SIGNATURE = 8,
	GET_NDS_ROM = 9,
	CHECK_DOWNLOAD_COMPLETE = 10,
	DISCONNECT = 11,
	
	-- responses
	AWAITNG_NAME = 1,
	NDS_ROM_CHUNK = 4,
	RSA_SIGNATURE = 3,
	DOWNLOAD_COMPLETE = 5,
	
	-- beacons
	
}


local function get_opcode_name(opcode)

	for key, value in pairs(g_opcodes) do
		if value == opcode then
			return key
		end
	end

	return "UNKNOWN_OPCODE"

end


local function set_ds_play_header(buffer, pinfo, tree, direction, method)
	local subtree = tree:add(dlplay, buffer(), dlplay.description .. " - " .. method)

	pinfo.cols.protocol = dlplay.description .. " (" .. direction .. ")"
	pinfo.cols.info = method
	
	return subtree
	
end


local function parse_request(buffer, pinfo, tree)
	
	if buffer(0,2):le_uint() == 0x8000 then
		local subtree = set_ds_play_header(buffer, pinfo, tree, request_string, "KEEP_ALIVE")
		Dissector.get("data"):call(buffer,pinfo,subtree)
		return true
	end
	
		
	local v_magic = buffer(0, 1)
	local magic = v_magic:le_uint()

	-- check magic number	
	if magic ~= 0x04 then
		return false
	end
	
	local v_port = buffer(1, 1)
	local flag = (v_port:le_uint() >> 4)
	local port = v_port:le_uint() & 0x0F
	

	local v_opcode = buffer(2, 1)
	local opcode = v_opcode:le_uint()
	local opcode_name = get_opcode_name(opcode)


	local v_seq = buffer(3, 1)
	local seq = v_seq:le_uint()
	

	local subtree = set_ds_play_header(buffer, pinfo, tree, request_string, opcode_name)


	subtree:add_le(t_magic, v_magic)
	subtree:add_le(t_port, v_port, port)

	-- check flag is non-0 then display flag
	if flag ~= 0 then
		subtree:add_le(t_flag, v_port, flag)
	end

	subtree:add_le(t_opcode, v_opcode, opcode )
	pinfo.columns["info"]:append(" op:" .. opcode)

	subtree:add_le(t_seq, v_seq, seq)
	pinfo.columns["info"]:append(" seq:" .. seq)
	
	local v_data = buffer(4)
	local length = buffer:len()

	if opcode == g_opcodes.SEND_DS_NAME then		
		if seq == 0 then

			local v_bytelen = v_data(4,1)
			local v_strlen = v_data(5,1)
			
			local strlen = v_strlen:le_uint()
			local bytelen = v_bytelen:le_uint()
			
			subtree:add_le(t_strlen, v_strlen, strlen)			
			subtree:add_le(t_bytelen, v_bytelen, bytelen)			
			
			pinfo.columns["info"]:append(" strlen:" .. strlen)
			pinfo.columns["info"]:append(" bytelen:" .. bytelen)

		else
			local name = v_data:le_ustring()
			subtree:add(t_name, v_data, name)			
			pinfo.columns["info"]:append(" data:" .. name)

		end
	elseif opcode == g_opcodes.GET_NDS_ROM then
		local v_offset = v_data(0,2)
		local offset = v_offset:uint()
		
		subtree:add(t_offset, v_offset, offset)	
		pinfo.columns["info"]:append(" offset:" .. offset)
		
	else
		Dissector.get("data"):call(v_data:tvb(),pinfo,subtree)
	end
	
	return true
end

local function parse_response(buffer, pinfo, tree)
	local length = buffer:len()

	local v_magic = buffer(0, 4)
	local magic = v_magic:uint()

	-- check magic number	
	if magic ~= 0x6010200 then
		return false
	end

	local v_flag = buffer(4, 1)
	local flag = v_flag:uint()

	local v_port = buffer(5, 1)
	local port = v_port:uint()

	local v_opcode = buffer(6, 1)
	local opcode = v_opcode:le_uint()
	local opcode_name = get_opcode_name(opcode)

	local v_seq = buffer(length-3, 1)
	seq = v_seq:le_uint()

	local v_footer = buffer(length-2)
	local footer = v_footer:int()

	local subtree = set_ds_play_header(buffer, pinfo, tree, response_string, opcode_name)
	
	-- add header
	subtree:add(t_resp_magic, v_magic, magic)
	subtree:add(t_resp_flag, v_flag, flag)
	subtree:add(t_resp_port, v_port, port)	

	subtree:add_le(t_resp_opcode, v_opcode, opcode)
	pinfo.columns["info"]:append(" op:" .. opcode)

	-- add offset
	if opcode == g_opcodes.NDS_ROM_CHUNK then
		local v_offset = buffer(7, 4)
		local offset = v_offset:le_uint() >> 16
		local v_data = buffer(11, length-11-3)
		
		-- provide offset into rom
		subtree:add_le(t_resp_offset, v_offset, offset)
		pinfo.columns["info"]:append(" offset:" .. offset)

		-- provide nds rom data
		Dissector.get("data"):call(v_data:tvb(),pinfo,subtree)
	elseif opcode == g_opcodes.RSA_SIGNATURE then
		local v_data = buffer(7, length-7-3)
		
		
		local v_arm9_entry 		=	v_data(0x00, 0x04)
		local v_arm7_entry 		=	v_data(0x04, 0x04)
		local v_header_dest_tmp =	v_data(0x0C, 0x04) 
		local v_header_dest 	=	v_data(0x10, 0x04)
		local v_header_len 		=	v_data(0x14, 0x04)
		local v_arm9_dest_tmp 	=	v_data(0x1C, 0x04)
		local v_arm9_dest 		=	v_data(0x20, 0x04)
		local v_arm9_size 		=	v_data(0x24, 0x04)
		local v_arm7_dest_tmp 	=	v_data(0x2C, 0x04) 
		local v_arm7_dest 		=	v_data(0x30, 0x04)
		local v_arm7_size 		=	v_data(0x34, 0x04)
		local v_rsa_header_end 	=	v_data(0x38, 0x04) 
		local v_rsa 			=	v_data(0x3C, 0x88)		
		
		
		local rsatree = subtree:add(dlplay, buffer(), "RSA Signature Block")
		
		rsatree:add	(t_sign_arm9_entry 		, v_arm9_entry 		)	
		rsatree:add	(t_sign_arm7_entry 		, v_arm7_entry 		)
		rsatree:add_le(t_sign_header_dest_tmp 	, v_header_dest_tmp )
		rsatree:add	(t_sign_header_dest 		, v_header_dest 	)
		rsatree:add	(t_sign_header_len 		, v_header_len 		)
		rsatree:add	(t_sign_arm9_dest_tmp 	, v_arm9_dest_tmp 	)
		rsatree:add	(t_sign_arm9_dest 		, v_arm9_dest 		)
		rsatree:add	(t_sign_arm9_size 		, v_arm9_size 		)
		rsatree:add_le(t_sign_arm7_dest_tmp 	, v_arm7_dest_tmp 	)
		rsatree:add	(t_sign_arm7_dest 		, v_arm7_dest 		)
		rsatree:add	(t_sign_arm7_size 		, v_arm7_size 		)
		rsatree:add_le(t_sign_rsa_header_end 	, v_rsa_header_end 	)
		rsatree:add	(t_sign_rsa 				, v_rsa 			)
		
	else 
		-- specify data
		local v_data = buffer(7, length-7-3)
		Dissector.get("data"):call(v_data:tvb(),pinfo,subtree)
	end
	
	
	-- non-0 is the packet is partial(?)
	subtree:add(t_resp_seq, v_seq, seq) 
	pinfo.columns["info"]:append(" seq:" .. seq)
	
	-- should be 0200
	subtree:add(t_resp_footer, v_footer, footer)
	
	return true
end

local function parse_keepalive(buffer, pinfo, tree)
	local length = buffer:len()	
	local subtree = set_ds_play_header(buffer, pinfo, tree, response_string, "KEEP_ALIVE")	
	
    subtree:add(t_random, buffer(0, 4))

	return true
end 

function dlplay.dissector(buffer, pinfo, tree)
	local subtree = set_ds_play_header(buffer, pinfo, tree, response_string, "ANNOUNCE")
	Dissector.get("data"):call(buffer,pinfo,subtree)

	
end
DissectorTable.get("wlan.tag.number"):add(0xDD, dlplay)

local function dlplay_heuristic_dissector(buffer, pinfo, tree)
	local keepalive = Address.ether("03:09:bf:00:00:03")
	local request = Address.ether("03:09:bf:00:00:10")
	local response = Address.ether("03:09:bf:00:00:00")
	
	-- cant figure out how to compare them properly
	if tostring(pinfo.dst) == tostring(keepalive) then
		-- parse keepalive
		return parse_keepalive(buffer, pinfo, tree)
	end
	if tostring(pinfo.dst) == tostring(request) then
		-- parse request
		return parse_request(buffer, pinfo, tree)
	end
	if tostring(pinfo.dst) == tostring(response) then
		-- parse response
		return parse_response(buffer, pinfo, tree)
	end
	
	return false
end

dlplay:register_heuristic("wlan_data", dlplay_heuristic_dissector)

