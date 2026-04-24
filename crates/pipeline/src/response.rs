use fingerprint_proxy_core::request::RequestContext;

pub fn set_response_status(ctx: &mut RequestContext, status: u16) {
    ctx.response.status = Some(status);
}

pub fn is_complete_response(ctx: &RequestContext) -> bool {
    ctx.response.status.is_some()
}
