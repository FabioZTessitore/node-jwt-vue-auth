import Vue from 'vue'
import router from '../../router';

const state = {
  status: '',
  token: '',//localStorage.getItem('user-token') || '',
  user: {}
};

const getters = {
  isLoggedIn: state => !!state.token,
  authStatus: state => state.status,
  user: state => state.user
};

const mutations = {
  auth_request: (state) => {
    state.status = 'loading'
    state.token = ''
    state.user = {}
  },
 
  auth_success: (state, { token, user }) => {
    state.status = 'success'
    state.token = token
    state.user = user
  },
 
  auth_error: (state) => {
    state.status = 'error'
    state.token = ''
    state.user = {}
  },
 
  auth_logout: (state) => {
    state.status = ''
    state.token = ''
    state.user = {}
  }
};

const actions = {
  'setLogoutTimer': ({ commit }, expirationTime) => {
    setTimeout(() => commit('auth_logout'), expirationTime * 1000)
  },

  'auth_request': ({ commit, dispatch }, { action, user }) => {
    return new Promise((resolve, reject) => {
      commit('auth_request')

      console.log(action, user)
      
      Vue.http.post(action, user)
      .then(response => {
        console.log('response', response)
        return response.json()
      })
      .then(data => {
        console.log('json response', data)
        commit('auth_success', { token: data.token, user: data.user })
        dispatch('setLogoutTimer', data.expiresIn)
        localStorage.setItem('user-token', data.token)
        const now = new Date()
        const expirationDate = new Date(now.getTime() + data.expiresIn*1000)
        localStorage.setItem('user-token-expirationDate', expirationDate)
        localStorage.setItem('user-id', data.user.id)
        resolve('ok')
      })
      .catch( err => {
        commit('auth_error')
        localStorage.removeItem('user-token')
        localStorage.removeItem('user-token-expirationDate')
        localStorage.removeItem('user-id')
        reject(err.body)
      })
    })
  },

  'auth_logout': ({ commit }) => {
      commit('auth_logout')
      localStorage.removeItem('user-token')
      router.replace('/login')
  },

  'tryLogin': ({ commit }) => {
    console.log('trylogin')
    const expirationTime = localStorage.getItem('user-token-expirationDate')
    const now = new Date()
    if (now >= expirationTime) {
      return
    }
    const token = localStorage.getItem('user-token')
    console.log(token)
    if (!token) {
      return
    }
    const userId = localStorage.getItem('user-id')
    commit('auth_success', {
      token: token,
      user: {
        id: userId
      }
    })

    Vue.http.get('/userdata/'+userId)
      .then(response => {
        console.log('response', response)
        return response.json()
      })
      .then(data => {
        console.log('json response', data)
        commit('auth_success', {
          token: token,
          user: data.user
        })

        router.replace('/dashboard')
      })
    
  },

  'secure_data': () => {
    return new Promise((resolve) => {
      console.log('loading secure data')

      Vue.http.get('/secure-data')
        .then(response => {
          console.log('response', response)
          return response.json()
        })
        .then(data => {
          console.log('json response', data)
          resolve(data)
        })
    })
  }
};

export default {
  state,
  getters,
  mutations,
  actions
};