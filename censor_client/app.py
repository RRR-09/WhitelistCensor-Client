import asyncio
import logging

import uvicorn
from censor_client import controller
from censor_client.models import RequestCensoredMessage, TempDataset
from censor_client.websocket_utils import BackgroundWebsocketProcess
from censor_client.twitch_utils import TwitchBot
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from rocketry import Rocketry
from rocketry.conds import every
from starlette import status
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request

fastapi_app = FastAPI(
    title="Whitelist Service - Client",
    description=(
        "Local HTTP server for the application to utilize local data or communicate with the central censor server"
    ),
)
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rocketry_app = Rocketry(execution="thread")

twitch_bot = TwitchBot()


class Server(uvicorn.Server):
    """Customized uvicorn.Server

    Disable uvicorn signal overrides, include Rocketry
    """

    def handle_exit(self, sig: int, frame) -> None:
        rocketry_app.session.shut_down()
        return super().handle_exit(sig, frame)


@rocketry_app.task(every("1 minute"), execution="thread")
async def check_sftp() -> None:
    while getattr(fastapi_app.state, "whitelist_data", None) is None:
        await asyncio.sleep(1)

    await controller.download_and_load_latest(fastapi_app.state)


@fastapi_app.on_event("startup")
async def startup_event() -> None:
    # setup logger
    logger = logging.getLogger("uvicorn.access")
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    fastapi_app.state.logger = logger

    # initialize or validate datafile structure
    controller.initialize_datafiles()

    # load data
    fastapi_app.state.whitelist_data = controller.load_data()

    # load misc. state
    fastapi_app.state.whitelist_state = controller.load_state()

    fastapi_app.state.whitelist_temp_data = TempDataset(custom=set(), usernames=set())

    # start central server link
    def add_to_temp_data(index: str, word: str):
        # TODO: Better way to do this
        fastapi_app.state.whitelist_temp_data[index].add(word)

    fastapi_app.state.ws_manager = BackgroundWebsocketProcess(
        add_to_temp_data, twitch_bot.send_twitch_message
    )

    asyncio.create_task(fastapi_app.state.ws_manager.main_loop())


@fastapi_app.on_event("shutdown")
async def shutdown_event() -> None:
    pass


@fastapi_app.exception_handler(RequestValidationError)
@fastapi_app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger = request.app.state.logger
    logger.error(f"{exc}")
    response = {
        "success": False,
        "errors": jsonable_encoder(str(exc)),
    }
    return JSONResponse(response, status_code=status.HTTP_400_BAD_REQUEST)


@fastapi_app.get("/")
async def read_root():
    return {"message": f"'{fastapi_app.title}' is currently up and running"}


@fastapi_app.post("/request_censored_message")
async def request_censored_message(
    req_body: RequestCensoredMessage, background_tasks: BackgroundTasks
):
    # TODO: Probably some way to cleanly disassemble this in function params
    username = req_body.username
    message = req_body.message
    try:
        censored_response = await controller.request_censored_message(
            fastapi_app.state.whitelist_data,
            fastapi_app.state.whitelist_state,
            username,
            message,
            fastapi_app.state.ws_manager,
            fastapi_app.state.whitelist_temp_data,
            background_tasks,
        )

        return JSONResponse(
            jsonable_encoder(censored_response), status_code=status.HTTP_200_OK
        )
    except Exception as e:
        return JSONResponse(str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


async def load_bot():
    try:
        twitch_bot.manual_init()
        asyncio.create_task(twitch_bot.connect())
    except Exception as e:
        print(f"[Twitch] Bot Loop Error:\n{e}\n\n")


async def async_main():
    "Run Rocketry and FastAPI"
    server = Server(
        config=uvicorn.Config(
            app=fastapi_app, workers=1, loop="asyncio", port=8086, reload=False
        )
    )

    api = asyncio.create_task(server.serve())
    scheduler = asyncio.create_task(rocketry_app.serve())
    twitch_bot_task = asyncio.create_task(load_bot())

    await asyncio.wait([api, scheduler, twitch_bot_task])


def init():
    # load settings
    load_dotenv(".env", verbose=True)
    controller.check_dotenv()

    # Print Rocketry's logs to terminal
    logger = logging.getLogger("rocketry.task")
    logger.addHandler(logging.StreamHandler())

    # Run both applications
    asyncio.run(async_main())


if __name__ == "__main__":
    init()
