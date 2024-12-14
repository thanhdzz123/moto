async function auth(req, rep) {
    if(req.cookies && req.cookies.token){
        try{
            const user = req.server.jwt.verify(req.cookies.token);
            req.user = user;
        } catch (error){
            rep.redirect(`/login?err=unAuth&url=${req.url}`);
        }
    }else{
        rep.redirect(`/login?err=unAuth&url=${req.url}`);
    }
}

module.exports = auth;