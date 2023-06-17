import { container } from 'tsyringe'
import { OPTIONS } from '../constants'
import { Fido2Provider } from './Fido2Provider'
import { Provider } from './Provider'

describe('Fido2Provider', () => {
  beforeAll(() => {
        container.register(OPTIONS, {
      useValue: {

      }
    })
  })
  // beforeEach(() => {
  //   container.reset()
  //   container.register(Fido2Provider, { useClass: Fido2Provider })
  //   container.register(OPTIONS, {
  //     useValue: {

  //     }
  //   })
  // })

  it('should be defined', () => {
    const instance = container.resolve(Fido2Provider)
    instance.challenge()
    console.log(container.resolveAll(Provider));

    expect(instance).toBeDefined()
  })
})
