import logging

import controller
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from models import RequestCensoredMessage
from starlette import status
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request

app = FastAPI(
    title="Whitelist Service - Client",
    description=(
        "Local HTTP server for the application to utilize local data or communicate with the central censor server"
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event() -> None:
    # setup logger
    logger = logging.getLogger("uvicorn.access")
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    app.state.logger = logger

    # load settings
    load_dotenv(".env", verbose=True)
    controller.check_dotenv()

    # initialize or validate datafile structure
    controller.initialize_datafiles()

    # load data
    app.state.whitelist_data = controller.load_data()

    # load misc. state
    app.state.whitelist_state = controller.load_state()


@app.on_event("shutdown")
async def shutdown_event() -> None:
    pass


@app.exception_handler(RequestValidationError)
@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger = request.app.state.logger
    logger.error(f"{exc}")
    response = {
        "success": False,
        "errors": jsonable_encoder(str(exc)),
    }
    return JSONResponse(response, status_code=status.HTTP_400_BAD_REQUEST)


@app.get("/")
def read_root():
    return {"message": f"'{app.title}' is currently up and running"}


@app.post("/request_censored_message")
def request_censored_message(req_body: RequestCensoredMessage):
    # TODO: Probably some way to cleanly disassemble this in function params
    username = req_body.username
    message = req_body.message
    try:
        censored_response = controller.request_censored_message(
            app.state.whitelist_data, app.state.whitelist_state, username, message
        )

        return JSONResponse(
            jsonable_encoder(censored_response), status_code=status.HTTP_200_OK
        )
    except Exception as e:
        return JSONResponse(str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


if __name__ == "__main__":
    uvicorn.run(app="main:app", port=8086, reload=False)
