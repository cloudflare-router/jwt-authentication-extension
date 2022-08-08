import { RouterRequest, RouterResponse } from "cloudflare-router";
import jsonwebtoken from "jsonwebtoken";


interface JwtAuthenticationOptions {
    /**
     * The JWT secret used for verifying JWT tokens
     */
    jwtSecret: string;
    /**
     * The header name where the JWT token can be located for the request.
     * Defaults to Authorization
     */
    headerName?: string;
    /**
     * Various handlers for scenarios
     */
    handlers?: {
        onNoHeaderProvided?: (req: RouterRequest, res: RouterResponse) => Promise<any>,
        onInvalidToken?: (req: RouterRequest, res: RouterResponse) => Promise<any>
    };
}


export default function JwtAuthentication (
    options: JwtAuthenticationOptions
) {
    const jwtSecret = options.jwtSecret;
    const headerName = options.headerName || "authorization";
    
    return async (req: RouterRequest, res: RouterResponse, next) => {
        const foundHeader = req.headers[headerName.toLowerCase()];
        
        if (!foundHeader) {
            if (options.handlers?.onNoHeaderProvided) {
                await options.handlers.onNoHeaderProvided(req, res);
            } else {
                res
                    .statusCode(401)
                    .text(`No authorization header found!`);
            }
            
            // Do not proceed with the request
            return next(false);
        }
        
        let validated: any = null;
        
        try {
            validated = jsonwebtoken.verify(
                foundHeader,
                jwtSecret
            );
        } catch (err) {
            validated = null;
        }
        
        if (!validated) {
            if (options.handlers?.onInvalidToken) {
                await options.handlers.onInvalidToken(req, res);
            } else {
                res
                    .statusCode(401)
                    .text(`Invalid authorization header!`);
            }
            
            // Invalid token
            return next(false);
        }
        
        
        // Assigning the JWT data to the JWT payload.
        res.locals.jwt = validated;
        
        return next();
    };
};
