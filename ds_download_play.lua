-- Opcode on :10
dlplay = Proto("DSDOWNLOADPLAY", "Nintendo DS Download Play")

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

-- get nds rom packet
local t_offset = ProtoField.uint16("dlplay.offset", "Offset", base.HEX)

-- response
local t_resp_magic = ProtoField.uint32("dlplay.resp.magic", "Magic", base.HEX)
local t_resp_ident = ProtoField.uint16("dlplay.resp.ident", "Identifier", base.HEX)
local t_resp_opcode = ProtoField.uint16("dlplay.resp.opcode", "Opcode", base.HEX)
local t_resp_offset = ProtoField.uint32("dlplay.resp.offset", "Offset", base.HEX)
local t_resp_flag = ProtoField.uint8("dlplay.resp.flag", "Flag", base.DEC)
local t_resp_footer = ProtoField.bytes("dlplay.resp.footer", "Footer")

-- keepalive
local t_random = ProtoField.uint32("dlplay.random", "Random", base.HEX)

-- strings
local request_string = "DS -> Station"
local response_string = "Station -> DS"


dlplay.fields = {
    t_magic, t_flag, t_port, t_opcode, t_seq, -- REQUEST packet general
	t_bytelen, t_strlen, t_name, -- SEND_DS_NAME packet
	t_offset, -- DOWNLOAD_NDS_ROM
	t_resp_magic, t_resp_ident, t_resp_opcode, t_resp_offset, t_resp_flag, t_resp_footer, -- RESPONSE packets
	t_random, -- KeepAlive packet
}

g_opcodes = {
	-- requests
	INITALIZE_DOWNLOAD = 0x00,
	SEND_DS_NAME = 0x07,
	AWAITING_RSA_SIGNATURE = 0x08,
	GET_NDS_ROM = 0x9,
	
	-- responses
	AWAITNG_NAME = 0x01,
	NDS_ROM_CHUNK = 0x04,
	RSA_SIGNATURE = 0x03
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

	local v_magic = buffer(0, 4)
	local magic = v_magic:uint()

	-- check magic number	
	if magic ~= 0x6010200 then
		return false
	end

	local v_identifier = buffer(4, 2)
	local identifier = v_identifier:uint()

	local v_opcode = buffer(6, 1)
	local opcode = v_opcode:le_uint()
	local opcode_name = get_opcode_name(opcode)

	local v_offset = buffer(7, 4)
	local offset = v_offset:le_uint() >> 16

	local subtree = set_ds_play_header(buffer, pinfo, tree, response_string, opcode_name)
	
	subtree:add(t_resp_magic, v_magic, magic)
	subtree:add(t_resp_ident, v_identifier, identifier)

	subtree:add_le(t_resp_opcode, v_opcode, opcode )
	pinfo.columns["info"]:append(" op:" .. opcode)

	-- add receive offset 
	subtree:add_le(t_resp_offset, v_offset, offset)
	if opcode == g_opcodes.NDS_ROM_CHUNK then
		pinfo.columns["info"]:append(" offset:" .. offset)
	end
	
	
	local length = buffer:len()
	local v_data = buffer(11, length-11-3)
	local v_footer = buffer(length-3)
	
	subtree:add(t_resp_footer, v_footer)
	
	Dissector.get("data"):call(v_data:tvb(),pinfo,subtree)
	return true
end

local function parse_keepalive(buffer, pinfo, tree)
	local length = buffer:len()	
	local subtree = set_ds_play_header(buffer, pinfo, tree, response_string, "KEEP_ALIVE")	
	
    subtree:add(t_random, buffer(0, 4))
	
	return true
end 

function dump(o)
   print(type(o))
   if type(o) == 'table' or type(o) == 'userdata' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function  dlplay.dissector(buffer, pinfo, tree)
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

dlplay:register_heuristic("wlan_data", dlplay.dissector)