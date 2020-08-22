import React from 'react';
// import logo from './logo.svg';
import './assets/css/style.css';
import './assets/css/custom.css';
import './assets/css/react.css'; 
import '../node_modules/bootstrap/dist/css/bootstrap.min.css';
import '../node_modules/fontawesome/index';

import parth from './img/founders/parth.jpeg';
import saurav from './img/founders/saurav.jpeg';
// import abhijeet from './img/heads/abhijeet.jpeg';
// import arun from './img/heads/arun.jpeg';
import './App.css';

function App() {
  return (
    <div className="main">
      <section className="team-section text-center my-5 section-bg" id="web">
        <div className="container">
          <div className="section-title aos-init aos-animate" data-aos="fade-up">
            <p>Founders</p>
          </div>
          <div className="row">
            <div className="col aos-init aos-animate" data-aos="zoom-in">
              <div className="aos-init aos-animate" data-aos="zoom-in">
                <div className="box">
                  <div className="imgBx">
                    <img src={parth} />
                  </div>
                  <ul className="social-icon">
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                  </ul>
                  <div className="details">
                    <p>Parth Wazulkar</p><br />
                  </div>
                </div>
                <p id="position" className="text-uppercase mb-0">Founder</p>
              </div>
            </div>
            <div className="col aos-init aos-animate" data-aos="zoom-in">
              <div className="aos-init aos-animate" data-aos="zoom-in">
                <div className="box">
                  <div className="imgBx">
                    <img src={saurav} />
                  </div>
                  <ul className="social-icon">
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                    <li><a href="/"><i className="fa fa-facebook" aria-hidden="true"></i></a>
                    </li>
                  </ul>
                  <div className="details">
                    <p>Saurav Dubey</p><br />
                  </div>
                </div>
                <p id="position" className="text-uppercase mb-0">Co-Founder</p>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section className="team-section text-center my-5" id="design">
        <div className="container">
          <div className="section-title aos-init aos-animate" data-aos="fade-up">
            <p>Heads</p>
          </div>
          <div className="row">
            <div className="col aos-init aos-animate" data-aos="zoom-in">
              <div className="aos-init aos-animate" data-aos="zoom-in">
                <div className="box">
                  <div className="imgBx">
                    <img src={parth} />
                  </div>
                  <ul className="social-icon">
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                  </ul>
                  <div className="details">
                    <p>Abhijeet Gupta</p><br />
                  </div>
                </div>
                <p className="text-uppercase mb-0" id="position">Community Head</p>
              </div>
            </div>
            <div className="col aos-init aos-animate" data-aos="zoom-in">
              <div className="aos-init aos-animate" data-aos="zoom-in">
                <div className="box">
                  <div className="imgBx">
                    <img src={parth} />
                  </div>
                  <ul className="social-icon">
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                    <li><a href="/"><i className="fa fa-" aria-hidden="true"></i></a></li>
                  </ul>
                  <div className="details">
                    <p>Arun Das</p><br />
                  </div>
                </div>
                <p className="text-uppercase mb-0" id="position">Development Head</p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

export default App;
