import { Controller, Module } from '@nestjs/common'

@Controller('passkeys')
export class PasskeysController {

}

@Module({
  controllers: [PasskeysController]
})
export class PasskeysModule {

}
