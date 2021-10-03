-- only one certification for one user by one other user
ALTER TABLE certifications ADD PRIMARY KEY (certifier_cert, target_cert)
